/* Exercise the actual static parsers without exposing a test-only public API. */
#include <assert.h>
#include "../tstat/udpL7.c"

regex_t re_ssl_subject, re_ssl_clean;

static void test_varints(void)
{
    static const struct {
        unsigned char bytes[8];
        size_t len;
        uint64_t value;
    } cases[] = {
        {{0x25}, 1, 37},
        {{0x3f}, 1, 63},
        {{0x40, 0x40}, 2, 64},
        {{0x7f, 0xff}, 2, 16383},
        {{0x80, 0, 0x40, 0}, 4, 16384},
        {{0x40, 0x25}, 2, 37},
        {{0x7b, 0xbd}, 2, 15293},
        {{0x9d, 0x7f, 0x3e, 0x7d}, 4, 494878333},
        {{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 8,
         UINT64_C(151288809941952652)},
        {{0xc0, 0, 0, 0, 0, 0, 0, 1}, 8, 1},
        {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 8,
         UINT64_C(0x3fffffffffffffff)}
    };
    size_t i, n, consumed;
    uint64_t value;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        unsigned char unaligned[9];
        memcpy(unaligned + 1, cases[i].bytes, cases[i].len);
        assert(read_var_len_int(unaligned + 1, cases[i].len, &value, &consumed));
        assert(value == cases[i].value && consumed == cases[i].len);
        for (n = 0; n < cases[i].len; n++) {
            unsigned char *short_input = malloc(n ? n : 1);
            memcpy(short_input, cases[i].bytes, n);
            value = 123;
            consumed = 99;
            assert(!read_var_len_int(short_input, n, &value, &consumed));
            assert(value == 123 && consumed == 99);
            free(short_input);
        }
    }
}

static size_t initial_header(unsigned char *packet, size_t token_len)
{
    size_t pos = 0;
    packet[pos++] = 0xc0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 1;
    packet[pos++] = 1;
    packet[pos++] = 0x42; /* DCID */
    packet[pos++] = 0;    /* SCID length */
    if (token_len < 64)
        packet[pos++] = token_len;
    else if (token_len < 16384) {
        packet[pos++] = 0x40 | (token_len >> 8);
        packet[pos++] = token_len & 0xff;
    }
    else {
        packet[pos++] = 0x80;
        packet[pos++] = 0;
        packet[pos++] = token_len >> 8;
        packet[pos++] = token_len & 0xff;
    }
    memset(packet + pos, 0, token_len);
    pos += token_len;
    packet[pos++] = 0x40;
    packet[pos++] = 20; /* packet number, ciphertext, tag */
    memset(packet + pos, 0, 20);
    return pos + 20;
}

static void test_headers(void)
{
    unsigned char packet[512];
    quic_hdr hdr;
    size_t n, len = initial_header(packet, 300);

    assert(parse_quic_hdr(packet, len, &hdr));
    assert(hdr.packet_number_offset == 312 && hdr.packet_end == len);
    /* Truncate each field and the payload, not just the last byte. */
    for (n = 0; n < len; n++) {
        unsigned char *short_input = malloc(n ? n : 1);
        memcpy(short_input, packet, n);
        memset(&hdr, 0xa5, sizeof(hdr));
        unsigned char unchanged[sizeof(hdr)];
        memcpy(unchanged, &hdr, sizeof(hdr));
        assert(!parse_quic_hdr(short_input, n, &hdr));
        assert(memcmp(&hdr, unchanged, sizeof(hdr)) == 0);
        free(short_input);
    }
    packet[5] = 21;
    assert(!parse_quic_hdr(packet, len, &hdr));
    len = initial_header(packet, 0);
    packet[7] = 21;
    assert(!parse_quic_hdr(packet, len, &hdr));
    len = initial_header(packet, 0);
    memset(packet + 1, 0, 4); /* Version Negotiation */
    assert(!parse_quic_hdr(packet, len, &hdr));
    packet[4] = 1;
    packet[0] = 0xf0; /* Retry */
    assert(!parse_quic_hdr(packet, len, &hdr));

    len = initial_header(packet, 0);
    size_t first_end = len;
    /* Coalesced 0-RTT with an eight-byte encoded Length of 20. */
    const unsigned char zero_rtt[] = {
        0xd0, 0, 0, 0, 1, 1, 0x42, 0,
        0xc0, 0, 0, 0, 0, 0, 0, 20
    };
    memcpy(packet + len, zero_rtt, sizeof(zero_rtt));
    len += sizeof(zero_rtt);
    memset(packet + len, 0, 20);
    len += 20;
    assert(parse_quic_hdr(packet, len, &hdr) && hdr.packet_end == first_end);
    assert(parse_quic_hdr(packet + first_end, len - first_end, &hdr));
    assert(hdr.packet_type == 1 && hdr.packet_end == len - first_end);

    unsigned char *datagram = calloc(1, 8 + len);
    struct udphdr *udp = (struct udphdr *)datagram;
    udp_pair pair = {0};
    pair.c2s.pup = pair.s2c.pup = &pair;
    udp->uh_ulen = htons(8 + len);
    memcpy(datagram + 8, packet, len);
    datagram[12] = 0x42; /* Test header classification without deriving Initial keys. */
    check_QUIC(NULL, udp, datagram + 8 + len - 1, &pair.c2s, &pair.s2c);
    assert(pair.c2s.QUIC_state == QUIC_OPEN_SENT);
    assert(pair.quic_zero_rtt == 1);
    free(pair.quic_client_hello);

    memset(&pair, 0, sizeof(pair));
    pair.c2s.pup = pair.s2c.pup = &pair;
    udp->uh_ulen = htons(8 + first_end - 1);
    check_QUIC(NULL, udp, datagram + 8 + len - 1, &pair.c2s, &pair.s2c);
    assert(pair.c2s.QUIC_state == QUIC_UNKNOWN && pair.quic_client_hello == NULL);
    free(datagram);
}

static void test_token_boundaries(void)
{
    const size_t lengths[] = {63, 64, 16383, 16384};
    size_t i;
    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        unsigned char *packet = malloc(lengths[i] + 64);
        assert(packet != NULL);
        size_t len = initial_header(packet, lengths[i]);
        size_t width = lengths[i] < 64 ? 1 : lengths[i] < 16384 ? 2 : 4;
        quic_hdr hdr;
        assert(parse_quic_hdr(packet, len, &hdr));
        assert(hdr.packet_number_offset == 10 + width + lengths[i]);
        assert(hdr.packet_end == len);
        free(packet);
    }

    unsigned char packet[128];
    size_t len = initial_header(packet, 64);
    packet[8] = 0x7f;
    packet[9] = 0xff; /* Claim a 16383-byte token in a much shorter datagram. */
    quic_hdr hdr;
    assert(!parse_quic_hdr(packet, len, &hdr));
}

static void test_control_packets(void)
{
    unsigned char client[128], datagram[256] = {0};
    const unsigned char controls[][29] = {
        /* Version Negotiation, followed by one advertised version. */
        {0xc0, 0, 0, 0, 0, 1, 0x42, 1, 0x24, 0, 0, 0, 0x43},
        /* Retry with a token and a placeholder integrity tag. */
        {0xf0, 0, 0, 0, 0x42, 1, 0x42, 1, 0x24, 't', 'o', 'k', 'n'}
    };
    const size_t control_lengths[] = {13, 29};
    unsigned char server[31] = {0xc0, 0, 0, 0, 0x42, 1, 0x42, 1, 0x24, 0, 20};
    struct udphdr *udp = (struct udphdr *)datagram;
    size_t i, len = initial_header(client, 0);
    client[4] = 0x42; /* Classification-only fixtures; no supported Initial keys. */

    for (i = 0; i < sizeof(control_lengths) / sizeof(control_lengths[0]); i++) {
        udp_pair pair = {0};
        pair.c2s.pup = pair.s2c.pup = &pair;
        udp->uh_ulen = htons(8 + len);
        memcpy(datagram + 8, client, len);
        check_QUIC(NULL, udp, datagram + 8 + len - 1, &pair.c2s, &pair.s2c);
        assert(pair.c2s.QUIC_state == QUIC_OPEN_SENT);

        udp->uh_ulen = htons(8 + control_lengths[i]);
        memcpy(datagram + 8, controls[i], control_lengths[i]);
        check_QUIC(NULL, udp, datagram + 8 + control_lengths[i] - 1,
                   &pair.s2c, &pair.c2s);
        assert(pair.c2s.QUIC_state == QUIC_OPEN_SENT);
        assert(pair.s2c.QUIC_state == QUIC_UNKNOWN);
        assert(!pair.c2s.is_QUIC && !pair.s2c.is_QUIC);

        udp->uh_ulen = htons(8 + sizeof(server));
        memcpy(datagram + 8, server, sizeof(server));
        check_QUIC(NULL, udp, datagram + 8 + sizeof(server) - 1,
                   &pair.s2c, &pair.c2s);
        assert(pair.c2s.is_QUIC && pair.s2c.is_QUIC);
        assert(pair.c2s.type == UDP_QUIC && pair.s2c.type == UDP_QUIC);
        free(pair.quic_client_hello);
    }
}

int main(void)
{
    test_varints();
    test_headers();
    test_token_boundaries();
    test_control_packets();
    puts("QUIC varint and header tests passed");
    return 0;
}
