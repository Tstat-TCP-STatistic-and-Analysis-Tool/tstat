#!/usr/bin/env python3
"""Replay synthetic Initial packets through Tstat and check exported UDP metadata."""
import argparse
import hashlib
import hmac
import ipaddress
from pathlib import Path
import struct
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

CID = bytes.fromhex("8394c8f03e515708")
SALTS = {
    1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0xFF00001D: bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899"),
    0xFACEB002: bytes.fromhex("c3eef712c72ebb5a11a7d2432bb46365bef9f502"),
    0xFACEB00E: bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899"),
}
CRYPTO = bytes.fromhex((Path(__file__).parent / "fixtures/rfc9001-client-crypto.hex").read_text())
HELLO = CRYPTO[4:]


def varint(value, width=None):
    width = width or next(n for n in (1, 2, 4, 8) if value < 1 << (8 * n - 2))
    return (value | ((width.bit_length() - 1) << (8 * width - 2))).to_bytes(width, "big")


def expand(secret, label, length):
    label = b"tls13 " + label
    info = struct.pack("!HB", length, len(label)) + label + b"\0"
    return HKDFExpand(hashes.SHA256(), length, info).derive(secret)


def initial(frames, pn=2, pn_len=4, token=b"", version=1, size=None):
    secret = hmac.new(SALTS[version], CID, hashlib.sha256).digest()
    client = expand(secret, b"client in", 32)
    key, iv, hp = (expand(client, label, length) for label, length in
                   ((b"quic key", 16), (b"quic iv", 12), (b"quic hp", 16)))
    if version == 1:
        assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"  # RFC 9001 A.1
    prefix = bytes([0xC0 | (pn_len - 1)]) + struct.pack("!I", version)
    prefix += bytes([len(CID)]) + CID + b"\0" + varint(len(token)) + token
    size = max(len(frames), 1200 - len(prefix) - 2 - pn_len - 16) if size is None else size
    assert len(frames) <= size
    pn_offset = len(prefix) + 2
    header = prefix + varint(pn_len + size + 16, 2) + pn.to_bytes(pn_len, "big")
    nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
    packet = bytearray(header + AESGCM(key).encrypt(nonce, frames.ljust(size, b"\0"), header))
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(bytes(packet[pn_offset + 4:pn_offset + 20]))
    packet[0] ^= mask[0] & 15
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[i + 1]
    return bytes(packet)


def crypto(data, offset=0, width=None):
    return b"\x06" + varint(offset, width) + varint(len(data), width) + data


def metadata_hello():
    hello = bytearray(HELLO)
    pos = 49
    while struct.unpack_from("!H", hello, pos)[0] != 0x39:
        pos += 4 + struct.unpack_from("!H", hello, pos + 2)[0]
    old_len = struct.unpack_from("!H", hello, pos + 2)[0]
    assert pos + 4 + old_len == len(hello)
    ua = b"test-client"
    param = varint(0x3129, 8) + varint(len(ua), 8) + ua
    struct.pack_into("!H", hello, pos + 2, old_len + len(param))
    hello += param + struct.pack("!HH", 0xFE0D, 32) + bytes(32)
    struct.pack_into("!H", hello, 47, len(hello) - 49)
    hello[1:4] = (len(hello) - 4).to_bytes(3, "big")
    return bytes(hello)


def cases():
    # Validate the fixture generator against RFC 9001 A.2, not Tstat's decoder.
    reference = initial(CRYPTO)
    assert reference[:22].hex() == "c000000001088394c8f03e5157080000449e7b9aec34"
    assert reference[22:38].hex() == "d1b1c98dd7689fb8ec11d242b123dc9b"
    assert reference[-16:].hex() == "e221af44860018ab0856972e194cd934"
    result = {}
    for pn_len, pn in ((1, 2), (2, 513), (3, 66051), (4, 16909060)):
        result[f"pn{pn_len}"] = ([initial(CRYPTO, pn, pn_len)], "example.com", "-", "0", "0")
    for version in SALTS:
        result[f"version-{version:x}"] = ([initial(CRYPTO, version=version)], "example.com", "-", "0", "0")
    result["token300"] = ([initial(CRYPTO, token=bytes(300))], "example.com", "-", "0", "0")
    result["metadata"] = ([initial(crypto(metadata_hello(), width=8))], "example.com", "test-client", "32", "0")
    result["reordered"] = ([initial(crypto(HELLO[64:], 64)), initial(crypto(HELLO[:64]), pn=3)], "example.com", "-", "0", "0")
    result["gap"] = ([initial(crypto(HELLO[:64])), initial(crypto(HELLO[65:], 65), pn=3)], "-", "-", "0", "0")
    # An independently length-delimited 0-RTT packet follows a valid Initial.
    zero_rtt = bytes.fromhex("d000000001088394c8f03e51570800") + varint(2048, 2) + bytes(2048)
    result["coalesced"] = ([reference + zero_rtt], "example.com", "-", "0", "1")
    result["limit1500"] = ([initial(CRYPTO, size=1500)], "example.com", "-", "0", "0")
    result["oversized"] = ([initial(CRYPTO, size=1501)], "-", "-", "0", "0")
    bad = bytearray(HELLO)
    bad[38] = 0xFF
    result["bad-session"] = ([initial(crypto(bytes(bad)))], "-", "-", "0", "0")
    result["short-hello"] = ([initial(crypto(HELLO[:-1]))], "-", "-", "0", "0")
    return result


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def packet(payload, port, reverse=False, ipv6=False):
    addresses = ("2001:db8::1", "2001:db8:1::1") if ipv6 else ("198.18.0.1", "198.19.0.1")
    src, dst = (ipaddress.ip_address(ip).packed for ip in addresses)
    sport, dport = port, 443
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    udp = struct.pack("!HHHH", sport, dport, len(payload) + 8, 0) + payload
    if ipv6:
        pseudo = src + dst + struct.pack("!I3xB", len(udp), 17)
        udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xFFFF) + udp[8:]
        header = struct.pack("!IHBB16s16s", 6 << 28, len(udp), 17, 64, src, dst)
    else:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, src, dst)
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    ethernet = bytes.fromhex("020000000002020000000001") + struct.pack("!H", 0x86DD if ipv6 else 0x0800)
    return ethernet + header + udp


def run(binary, directory, selected, ipv6=False):
    directory.mkdir(parents=True, exist_ok=True)
    trace = directory / "quic.pcap"
    with trace.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        timestamp = 1700000000
        for i, (_, (payloads, *_)) in enumerate(selected.items()):
            # Only the server's clear long header is needed for flow classification.
            server = bytes.fromhex("c000000001088394c8f03e5157080833333333333333330014") + bytes(20)
            version = payloads[0][1:5]
            server = server[:1] + version + server[5:]
            for payload, reverse in [(p, False) for p in payloads] + [(server, True)]:
                frame = packet(payload, 40000 + i, reverse, ipv6)
                stream.write(struct.pack("<IIII", timestamp, 0, len(frame), len(frame)) + frame)
                timestamp += 1
    output = directory / "output"
    completed = subprocess.run([str(binary), "-s", str(output), str(trace)], text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    (directory / "tstat-output.txt").write_text(completed.stdout)
    assert completed.returncode == 0, completed.stdout
    logs = list(output.rglob("log_udp_complete"))
    assert len(logs) == 1, f"Expected one UDP log, found {logs}"
    lines = logs[0].read_text().splitlines()
    columns = {field.rsplit(":", 1)[0].lstrip("#"): int(field.rsplit(":", 1)[1]) - 1
               for field in lines[0].split()}
    rows = {int(row[columns["c_port"]]): row for row in
            (line.split() for line in lines[1:] if line and not line.startswith("#"))}
    assert len(rows) == len(selected), f"Expected {len(selected)} flows, got {len(rows)}"
    for i, (name, (_, sni, ua, ech, zero_rtt)) in enumerate(selected.items()):
        row = rows[40000 + i]
        expected = {"c_type": "27", "s_type": "27", "quic_SNI": sni,
                    "quic_UA": ua, "quic_ech": ech, "quic_zero_rtt": zero_rtt}
        for field, value in expected.items():
            assert row[columns[field]] == value, f"{name}: {field}: expected {value}, got {row[columns[field]]}"
        print(f"PASS {name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--case", choices=list(cases()))
    parser.add_argument("--keep", type=Path, help="retain the generated pcap and logs for manual inspection")
    parser.add_argument("--ipv6", action="store_true", help="replay the same cases over IPv6")
    args = parser.parse_args()
    selected = cases()
    if args.case:
        selected = {args.case: selected[args.case]}
    if args.keep:
        run(args.binary.resolve(), args.keep.resolve(), selected, args.ipv6)
    else:
        with tempfile.TemporaryDirectory(prefix="tstat-quic-") as tmp:
            run(args.binary.resolve(), Path(tmp), selected, args.ipv6)
