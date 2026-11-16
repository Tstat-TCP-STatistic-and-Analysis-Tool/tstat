# QUIC regressions

On Ubuntu, install the dependencies listed in the main README, then run:

```sh
make test
```

The C test includes `udpL7.c` to exercise its static functions. Linker garbage
collection excludes unrelated plugins; no production API is added for testing.
Cases cover RFC 9000 varints, truncation at each field boundary, a token longer
than 255 bytes, token encoding boundaries at 63/64 and 16383/16384, and
coalesced packet offsets and classification. Version Negotiation and Retry
are not parsed as Initial packets; tests verify that they leave a pending
flow intact and a subsequent server Initial still classifies both directions.
These header-only fixtures deliberately skip Initial key derivation; full
decryption and packet replay are covered by the follow-up PR.

For address and undefined-behavior checks (Clang shown below; GCC also works):

```sh
UBSAN_OPTIONS=halt_on_error=1 ASAN_OPTIONS=detect_leaks=1 \
make -B test CC=clang \
  CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined'
```

Use `-B` when changing flags so the test executable is rebuilt.
The same sanitizer command works with GCC: replace `CC=clang` with `CC=gcc`.

The CRYPTO tests also cover out-of-order fragments, gaps, conflicting
retransmissions, and ClientHello/extension bounds. The fixture is the CRYPTO
frame from [RFC 9001 Appendix A.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-A.2).

To check the executable and UDP log writer over IPv4 and IPv6:

```sh
sudo apt-get install python3-cryptography
make test-pcap
```

The Python test generates Initial packets using an independent crypto library
and checks its generator against the published RFC 9001 key, protected header,
ciphertext sample, and tag. It checks all packet-number widths, the supported
salt families, long tokens, SNI/UA/ECH output, reordered or missing CRYPTO data,
coalescing, and the 1500-byte plaintext limit. It reads column indexes from the
exported header. The server packet and coalesced 0-RTT payload are synthetic;
these tests do not emulate a complete TLS exchange.

For manual inspection, retain one capture and its logs in a new directory:

```sh
review_dir=$(mktemp -d)
python3 tests/test_quic_pcap.py ./tstat/tstat --case reordered --keep "$review_dir"
tcpdump -nr "$review_dir/quic.pcap"
cat "$review_dir"/output/*/log_udp_complete
```

Expect one UDP flow classified as QUIC in both directions, with `quic_SNI`
equal to `example.com`. For `--case short-hello`, expect `quic_SNI` to be `-`.
Use a different new directory for each run. Plaintext exceeding 1500 bytes is
skipped for metadata extraction; the flow can still be classified as QUIC.

For the full executable under sanitizers, clean first and rebuild both C and C++
objects with matching flags:

```sh
make clean
make all libtstat CC=clang CXX=clang++ \
  CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  CXXFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined'
UBSAN_OPTIONS=halt_on_error=1 ASAN_OPTIONS=detect_leaks=1 make test-pcap
```
