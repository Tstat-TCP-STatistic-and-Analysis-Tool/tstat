/*
 *
 * Copyright (c) 2001-2008
 *	Politecnico di Torino.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * For bug report and other information please visit Tstat site:
 * http://tstat.polito.it
 *
 * The payload matching functions are derived from IPP2P, an extension to
 * iptables to identify P2P traffic, written by Eicke Friedrich and
 * Klaus Degner <ipp2p@ipp2p.org>
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/

/*
 * Layer 7 classification of UDP flows (DNS, DTLS and Multiplexed TURN)
 * and generation of log_udp_complete.
 * QUIC is identified by its long header handshake, and the SNI is extracted
 * decrypting the client Initial packet.
 * RTP/RTCP are identified by the RTP plugin (rtp.c).
 */

#include <openssl/evp.h>
#include <regex.h>

#include "tstat.h"
#include "tcpL7.h"
#include "rfc6234/sha.h"

#define get_u8(X,O)   (*(tt_uint8  *)(X + O))
#define get_u16(X,O)  (*(tt_uint16 *)(X + O))

#define QUIC_MAX_ACCUL 15000
#define QUIC_MAX_PKT 1500
#define QUIC_MAX_SNI_PKT 10

extern FILE *fp_udp_logc;
extern regex_t re_ssl_subject,re_ssl_clean;

/* Search for DNS queries and responses */
static enum udp_type
udp_search_dns (unsigned char *haystack, int packet_len, int payload_len)
{
  unsigned char *t = haystack;
  t += 8;

  /* Following the example of L7 Filter, we match QUESTION (either 1 or 2)
     at (offset 4-5) and the fact that the queries start with 0x01-0x3F
     followed by [a-z0-9] (offset 12-13).
     This should be enough if we have at least 22 bytes in the payload.
     If we have more bytes, we look for the most common types, i.e.
     Type (0x0001-0x0010, 0x001c, 0x0021,0x002e, 0x0040 and 00x0041)
     and Class (0x01,0x03,0x04,0xff), that are located after the Name
     termination 0x00.
     This rule does not match the refused responses for Dynamic Update,
     because Zones (i.e. Question) is 0. The corresponding queries are
     matched. It also doesn't match a few esoteric queries. */

  if (!(t[4] == 0 && (t[5] == 0x01 || t[5] == 0x02)))
    return UDP_UNKNOWN;

  if (t[12] < 0x01 || t[12] > 0x3F)
    return UDP_UNKNOWN;

  if (!((t[13] >= 0x61 && t[13] <= 0x7a) || (t[13] >= 0x41 && t[13] <= 0x5a)
	|| (t[13] >= 0x30 && t[13] <= 0x39)))
    return UDP_UNKNOWN;

  if (payload_len > 22)
    {
      int idx = 14;
      while (idx < payload_len - 8)
	{
	  if (t[idx] == 0)
	    break;
	  idx++;
	}

      if (idx < payload_len - 12)
	{
	  if (t[idx + 1] == 0 &&
	      ((t[idx + 2] >= 0x01 && t[idx + 2] <= 0x10) || t[idx + 2] == 0x1c ||
	       t[idx + 2] == 0x40 || t[idx + 2] == 0x41 ||	/* SVCB / HTTPS */
	       t[idx + 2] == 0x21 || t[idx + 2] == 0x2e ||	/* SRV / RRSIG */
	       (t[idx + 2] == 0xff || t[idx + 2] == 0xfd || t[idx + 2] == 0xfc)	/* QTYPEs */
	      ) &&
	      t[idx + 3] == 0 &&
	      (t[idx + 4] == 0x01 || t[idx + 4] == 0x03 || t[idx + 4] == 0x04
	       || t[idx + 4] == 0xFF))
	    return DNS;
	  else
	    return UDP_UNKNOWN;
	}
    }

  return DNS;
}

/* Search for DTLS handshake messages */
static enum udp_type
udp_search_dtls (unsigned char *haystack, int packet_len, int payload_len)
{
  unsigned char *t = haystack;
  t += 8;

  if (t[0] == 0x16 &&		/* Client Handshake */
      t[1] == 0xFE &&		/* 255-1 (TLS 1.x) */
      t[2] >= 0xFB &&		/* 255-x (TLS 1.x) */
      t[11] <= 0x39)
    return UDP_DTLS;

  return UDP_UNKNOWN;
}

/* Search for Multiplexed TURN messages (used by Skype and MS Teams) */
static enum udp_type
udp_search_mturn (unsigned char *haystack, int packet_len, int payload_len)
{
  /* byte 1 (8): 0xff
     byte 2 (9): 0x10
     byte 3-4 (10-11): payload length */
  if (get_u8 (haystack, 8) != 0xff || get_u8 (haystack, 9) != 0x10)
    return UDP_UNKNOWN;

  if (ntohs (get_u16 (haystack, 10)) != packet_len - 12)
    return UDP_UNKNOWN;

  return UDP_MTURN;
}

struct udpmatch
{
  int min_len;			/* minimum UDP length (header included) */
  enum udp_type (*match) (unsigned char *, int, int);
};

/* Matching functions, tested in this order */
static struct udpmatch udp_list[] = {
  {22, &udp_search_dns},
  {25, &udp_search_dtls},
  {22, &udp_search_mturn},
  {0, NULL}
};

void *
getudpL7 (struct udphdr *pudp, int tproto, void *pdir, void *plast)
{
  /* just pass the complete packet and let udpL7_flow_stat decide */
  return (void *) pudp;
}

/* DNS, DTLS and MTURN classification */
static void
udpL7_dpi (void *pproto, ucb *udir, void *hdr, void *plast)
{
  unsigned char *haystack = (unsigned char *) hdr;
  int packet_len, data_len, i;
  enum udp_type type;

  /* each flow is classified only once, looking at its first packets */
  if (udir->type != UDP_UNKNOWN || udir->packets > MAX_UNKNOWN_PACKETS)
    return;

  /* UDP length, header included */
  packet_len = ntohs (((struct udphdr *) pproto)->uh_ulen);
  data_len = (unsigned char *) plast - haystack + 1;

  for (i = 0; udp_list[i].match != NULL; i++)
    {
      if (packet_len > udp_list[i].min_len)
	{
	  type = udp_list[i].match (haystack, packet_len, data_len);
	  if (type != UDP_UNKNOWN)
	    {
	      udir->type = type;
	      return;
	    }
	}
    }
}

/*-------------------------------------------------------------------*/
/* QUIC                                                              */
/*-------------------------------------------------------------------*/

typedef struct {
  uint8_t header_form   : 1;
  uint8_t fixed_bit     : 1;
  uint8_t spin_bit      : 1;
  uint8_t packet_type   : 2;
  uint8_t reserved      : 2;
  uint8_t packet_nb_len : 2;
  uint8_t version[4]       ;
  uint8_t dcid_len         ;
  uint8_t dcid[20]         ;
  uint8_t scid_len         ;
  uint8_t scid[20]         ;
  size_t packet_number_offset;
  size_t packet_end;
} quic_hdr;


/* Read Variable Length Integers
   As Defined in: RFC 9000, Section 16
   Input: start
   Output: result, offset (in Bytes)
*/
static int read_var_len_int(const uint8_t *start, size_t remaining,
                            uint64_t *result, size_t *consumed){
    size_t len, i;
    uint64_t value;

    if (remaining == 0)
        return 0;
    len = (size_t)1 << (start[0] >> 6);
    if (len > remaining)
        return 0;
    value = start[0] & 0x3f;
    for (i = 1; i < len; i++)
        value = (value << 8) | start[i];
    *result = value;
    *consumed = len;
    return 1;
}


/* Salt used to derive the Initial secrets [RFC 9001, Section 5.2].
   Drafts 23-28 and 29-32 share the same salt; Meta's mvfst versions
   0xfaceb002 and 0xfaceb00e follow draft-27 and draft-29 respectively.
   Returns NULL for unsupported versions (e.g., QUIC v2, which also
   changes the HKDF labels). */
static const unsigned char *quic_initial_salt(const uint8_t *version){

    static const unsigned char salt_v1[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    static const unsigned char salt_draft29[20] = {
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
        0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
    };
    static const unsigned char salt_draft23[20] = {
        0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
        0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02
    };
    uint32_t v = ((uint32_t)version[0] << 24) | ((uint32_t)version[1] << 16) |
                 ((uint32_t)version[2] << 8) | version[3];

    if (v == 0x00000001)
        return salt_v1;
    if ((v >= 0xff00001d && v <= 0xff000020) || v == 0xfaceb00e)
        return salt_draft29;
    if ((v >= 0xff000017 && v <= 0xff00001c) || v == 0xfaceb002)
        return salt_draft23;
    return NULL;
}

struct quic_crypto_buffer {
    unsigned char data[QUIC_MAX_ACCUL];
    unsigned char received[(QUIC_MAX_ACCUL + 7) / 8];
};

static void accumulate_QUIC_crypto(udp_pair *pup, const unsigned char *data, size_t len){
    size_t pos = 0, consumed;
    uint64_t type, offset, length;

    while (pos < len){
        if (!read_var_len_int(data + pos, len - pos, &type, &consumed))
            return;
        pos += consumed;
        if (type == 0 || type == 1) /* PADDING or PING */
            continue;
        if (type != 6) /* Stop at a frame we cannot skip safely. */
            return;
        if (!read_var_len_int(data + pos, len - pos, &offset, &consumed))
            return;
        pos += consumed;
        if (!read_var_len_int(data + pos, len - pos, &length, &consumed))
            return;
        pos += consumed;
        if (length > len - pos || offset > QUIC_MAX_ACCUL ||
            length > QUIC_MAX_ACCUL - offset)
            return;
        if (length != 0){
            struct quic_crypto_buffer *buffer = pup->quic_client_hello;
            if (buffer == NULL){
                buffer = calloc(1, sizeof(*buffer));
                if (buffer == NULL)
                    return;
                pup->quic_client_hello = buffer;
            }
            /* Retransmitted bytes must agree with the bytes already collected. */
            size_t i;
            for (i = 0; i < length; i++){
                size_t at = (size_t)offset + i;
                if ((buffer->received[at / 8] & (1u << (at % 8))) &&
                    buffer->data[at] != data[pos + i])
                    return;
            }
            memcpy(buffer->data + offset, data + pos, (size_t)length);
            for (i = 0; i < length; i++){
                size_t at = (size_t)offset + i;
                buffer->received[at / 8] |= 1u << (at % 8);
            }
            while (pup->quic_client_hello_len < QUIC_MAX_ACCUL){
                size_t at = pup->quic_client_hello_len;
                if (!(buffer->received[at / 8] & (1u << (at % 8))))
                    break;
                pup->quic_client_hello_len++;
            }
        }
        pos += (size_t)length;
    }
}

static void search_QUIC_client_hello(ucb *thisdir, const unsigned char *data,
                                      const quic_hdr *hdr){
    int err, plaintext_len, len;
    EVP_CIPHER_CTX *ctx;
    unsigned char plaintext[QUIC_MAX_PKT], mask[16];
    size_t pn_offset = hdr->packet_number_offset;
    size_t packet_end = hdr->packet_end;
    int conn_id_len = hdr->dcid_len;

    /* Header protection samples 16 bytes starting four bytes after PN offset. */
    if (hdr->packet_type != 0 || packet_end - pn_offset < 20)
        return;
    // Get initial secrets [RFC 9001, Section 5.4.1]
    // Example in Appendix from https://datatracker.ietf.org/doc/html/rfc9001
    
    // The salt depends on the version. Must be updated in future versions
    const unsigned char *salt = quic_initial_salt(hdr->version);
    if (salt == NULL)
        return;

    /* HKDF-{Extract,Expand} Functions from TLS 1.3 [RFC 8446 Section 7.1 and RFC 5869 Section 2.2 and 2.3] */
    unsigned char initial_secret[USHAMaxHashSize];
    err = hkdfExtract(SHA256, salt, 20, (const unsigned char *)thisdir->QUIC_conn_id, conn_id_len, initial_secret);
    if (err !=0)
      return;
    
    /* Client Initial Secret */
    static const unsigned char HkdfLabel_client_initial_secret[19] =
        {0x00, 0x20, 0x0F, 't', 'l', 's', '1', '3', ' ', 'c', 'l', 'i', 'e', 'n', 't', ' ', 'i', 'n', 0x00};
    unsigned char client_initial_secret[32];     
    err = hkdfExpand(SHA256, initial_secret, 32, HkdfLabel_client_initial_secret, 19,
                            client_initial_secret, 32);
    if (err !=0)
        return;

    //  Key
    static const unsigned char HkdfLabel_key[18] =
        {0x00, 0x10, 0x0E, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'k', 'e', 'y', 0x00};    
    unsigned char key[16];  
    err = hkdfExpand(SHA256, client_initial_secret, SHA256HashSize, HkdfLabel_key, 18,
                             key, 16);
    if (err !=0)
        return;

    // Initialization Vector
    static const unsigned char HkdfLabel_iv[17] =
        {0x00, 0x0C, 0x0D, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'i', 'v', 0x00};
        
    unsigned char iv[12];  
    err = hkdfExpand(SHA256, client_initial_secret, SHA256HashSize, HkdfLabel_iv, 17,
                             iv, 12);
    if (err !=0)
        return;

    // Header Protection
    static const unsigned char HkdfLabel_hp[17] =
        {0x00, 0x10, 0x0D, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'h', 'p', 0x00};
    unsigned char hp[16];  
    err = hkdfExpand(SHA256, client_initial_secret, SHA256HashSize, HkdfLabel_hp, 17,
                             hp, 16);
    if (err !=0)
        return;


    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hp, NULL) != 1 ||
        EVP_EncryptUpdate(ctx, mask, &len, data + pn_offset + 4, 16) != 1){
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    EVP_CIPHER_CTX_free(ctx);

    size_t pn_len = (hdr->packet_nb_len ^ (mask[0] & 3)) + 1;
    size_t payload_offset = pn_offset + pn_len;
    size_t ciphertext_len = packet_end - payload_offset - 16;
    /* Oversized Initials remain classifiable, but cannot supply metadata. */
    if (ciphertext_len > sizeof(plaintext))
        return;
    uint32_t pkn = 0;
    size_t i;
    for (i = 0; i < pn_len; i++)
        pkn = (pkn << 8) | (data[pn_offset + i] ^ mask[i + 1]);
    for (i = 0; i < 4; i++)
        iv[sizeof(iv) - 1 - i] ^= (unsigned char)(pkn >> (i * 8));

    /* As before, metadata is extracted without verifying the AEAD tag. */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, data + payload_offset,
                          (int)ciphertext_len) != 1){
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    EVP_CIPHER_CTX_free(ctx);
    accumulate_QUIC_crypto(thisdir->pup, plaintext, (size_t)plaintext_len);
}

static unsigned int quic_u16(const unsigned char *data){
    return ((unsigned int)data[0] << 8) | data[1];
}

static void search_QUIC_SNI(ucb *thisdir){
    udp_pair *pup = thisdir->pup;
    const struct quic_crypto_buffer *buffer = pup->quic_client_hello;
    if (buffer == NULL || pup->quic_client_hello_len < 4)
        return;
    const unsigned char *data = buffer->data;
    size_t hello_len = 4 + ((size_t)data[1] << 16) + ((size_t)data[2] << 8) + data[3];
    if (data[0] != 1 || hello_len > pup->quic_client_hello_len || hello_len < 38)
        return;

    size_t pos = 38, length;
    if (pos == hello_len)
        return;
    length = data[pos++]; /* legacy_session_id */
    if (length > 32 || length > hello_len - pos)
        return;
    pos += length;
    if (hello_len - pos < 2)
        return;
    length = quic_u16(data + pos); /* cipher_suites */
    pos += 2;
    if (length < 2 || length % 2 != 0 || length > hello_len - pos)
        return;
    pos += length;
    if (hello_len - pos < 2 || data[pos] != 1 || data[pos + 1] != 0)
        return; /* TLS 1.3 legacy_compression_methods = {0}. */
    pos += 2;
    if (hello_len - pos < 2 || quic_u16(data + pos) != hello_len - pos - 2)
        return;
    pos += 2;

    char sni[80] = {0}, ua[81] = {0};
    int have_sni = 0, have_ua = 0, have_ech = 0;
    unsigned int ech_len = 0;
    while (pos < hello_len){
        if (hello_len - pos < 4)
            return;
        unsigned int type = quic_u16(data + pos);
        size_t ext_len = quic_u16(data + pos + 2);
        pos += 4;
        if (ext_len > hello_len - pos)
            return;
        const unsigned char *ext = data + pos;
        size_t at = 0;
        if (type == 0){ /* ServerNameList */
            if (ext_len < 2 || quic_u16(ext) != ext_len - 2)
                return;
            at = 2;
            while (at < ext_len){
                if (ext_len - at < 3)
                    return;
                unsigned int name_type = ext[at];
                size_t name_len = quic_u16(ext + at + 1);
                at += 3;
                if (name_len == 0 || name_len > ext_len - at)
                    return;
                if (name_type == 0){
                    if (have_sni || name_len >= sizeof(sni) ||
                        memchr(ext + at, 0, name_len) != NULL)
                        return;
                    memcpy(sni, ext + at, name_len);
                    have_sni = 1;
                }
                at += name_len;
            }
        }
        else if (type == 0x0039){ /* QUIC transport parameters */
            while (at < ext_len){
                uint64_t param_type, param_len;
                size_t consumed;
                if (!read_var_len_int(ext + at, ext_len - at, &param_type, &consumed))
                    return;
                at += consumed;
                if (!read_var_len_int(ext + at, ext_len - at, &param_len, &consumed))
                    return;
                at += consumed;
                if (param_len > ext_len - at)
                    return;
                if (param_type == 0x3129 && !have_ua){
                    size_t copied = min(sizeof(ua) - 1, param_len);
                    memcpy(ua, ext + at, copied);
                    have_ua = 1;
                }
                at += (size_t)param_len;
            }
        }
        else if (type == 0xfe0d){
            have_ech = 1;
            ech_len = ext_len;
        }
        pos += ext_len;
    }

    /* Commit metadata only after the whole ClientHello has passed its bounds checks. */
    if (have_sni && pup->quic_sni_name == NULL &&
        regexec(&re_ssl_subject, sni, 0, NULL, 0) == 0 &&
        regexec(&re_ssl_clean, sni, 0, NULL, 0) == 0)
        pup->quic_sni_name = url_encode(sni);
    if (have_ua && pup->quic_ua_string == NULL)
        pup->quic_ua_string = url_encode(ua);
    if (have_ech)
        pup->quic_ech = ech_len;
}


/* Offsets are relative to the start of the QUIC packet, without the UDP header. */
static int parse_quic_hdr(const unsigned char *base, size_t data_len, quic_hdr *out){
    quic_hdr hdr = {0};
    size_t pos, consumed;
    uint64_t token_len, packet_len;

    if (data_len < 7 || (base[0] & 0xc0) != 0xc0)
        return 0;
    hdr.header_form = 1;
    hdr.fixed_bit = 1;
    hdr.packet_type = (base[0] >> 4) & 3;
    hdr.packet_nb_len = base[0] & 3; /* Still protected. */
    memcpy(hdr.version, base + 1, 4);
    if (!(base[1] | base[2] | base[3] | base[4]) || hdr.packet_type == 3)
        return 0; /* Version Negotiation and Retry do not carry a Length field. */

    pos = 5;
    hdr.dcid_len = base[pos++];
    if (hdr.dcid_len > sizeof(hdr.dcid) || hdr.dcid_len >= data_len - pos)
        return 0;
    memcpy(hdr.dcid, base + pos, hdr.dcid_len);
    pos += hdr.dcid_len;
    hdr.scid_len = base[pos++];
    if (hdr.scid_len > sizeof(hdr.scid) || hdr.scid_len > data_len - pos)
        return 0;
    memcpy(hdr.scid, base + pos, hdr.scid_len);
    pos += hdr.scid_len;

    if (hdr.packet_type == 0){
        if (!read_var_len_int(base + pos, data_len - pos, &token_len, &consumed))
            return 0;
        pos += consumed;
        if (token_len > data_len - pos)
            return 0;
        pos += (size_t)token_len;
    }
    if (!read_var_len_int(base + pos, data_len - pos, &packet_len, &consumed))
        return 0;
    pos += consumed;
    /* At least one packet-number byte and the 16-byte authentication tag. */
    if (packet_len < 17 || packet_len > data_len - pos)
        return 0;
    hdr.packet_number_offset = pos;
    hdr.packet_end = pos + (size_t)packet_len;
    *out = hdr;
    return 1;
}


static void check_QUIC(struct ip * pip, struct udphdr * pudp, void *plast,
                ucb *thisdir, ucb *otherdir)
{
  int payload_len;
  int data_len;
  unsigned char *base;

  /* Flow already classified, not worth still searching SNI */
  if ((thisdir->is_QUIC==1 && otherdir->is_QUIC==1) && ( thisdir->packets > QUIC_MAX_SNI_PKT))
    return;  

  /* This is the UDP complete length, included the header size */
  payload_len = ntohs (pudp->uh_ulen);

  base = (unsigned char *) pudp;
  data_len = (unsigned char *) plast - (unsigned char *) base + 1;

  if (data_len < 8 || payload_len < 8)
    return;
  if (data_len > payload_len)
    data_len = payload_len;

  quic_hdr hdr;
  if (!parse_quic_hdr(base + 8, (size_t)data_len - 8, &hdr))
    return;


  /* New code for Google QUIC Version >= 46 (QUIC IETF) */
  if( (thisdir->QUIC_state == QUIC_UNKNOWN) ||  (thisdir->QUIC_state == QUIC_OPEN_SENT) ){
        /* MATCHING QUIC IETF
           We only have part of the header in clear.
           We match the DCID with SCID and version across "Initial" (or "0-RTT") packets */

        // Look for initial well-formed packets
        if ( hdr.header_form == 1 && hdr.packet_type == 0 &&
             hdr.fixed_bit == 1   &&
             hdr.dcid_len <= 20   && hdr.scid_len <= 20  ){
        
            memcpy(thisdir->QUIC_conn_id,hdr.dcid,hdr.dcid_len); // Save the connection ID
            
            // Look for Client Packets with DCID in case in state UNK
            if ( hdr.dcid_len > 0 && otherdir->QUIC_state != QUIC_OPEN_SENT){
                memcpy(thisdir->pup->quic_c_vers,hdr.version,4); // Save the version
                thisdir->QUIC_state=QUIC_OPEN_SENT; // Set is as "open", we have see an "Initial" packet
            } 
            
            // Look for Server Packets with SCID in case in state QUIC_OPEN_SENT
            else if ( hdr.scid_len > 0 && otherdir->QUIC_state == QUIC_OPEN_SENT){
                memcpy(thisdir->pup->quic_s_vers,hdr.version,4); // Save the version
                
                if ( memcmp(thisdir->pup->quic_c_vers, thisdir->pup->quic_s_vers, 4) == 0 ){
                    thisdir->QUIC_state = otherdir->QUIC_state = QUIC_DATA_SENT; // Mark the flow forever
                    thisdir->is_QUIC = otherdir->is_QUIC = 1;
                }
                
            }
            /* A coalesced packet starts after the complete Length-delimited packet. */
            size_t next = 8 + hdr.packet_end;
            quic_hdr hdr_second;
            if (parse_quic_hdr(base + next, data_len - next, &hdr_second) &&
                hdr_second.packet_type == 1)
                thisdir->pup->quic_zero_rtt += 1;
        }              
                  
        // Look for inflight 0-rtt
        else if ( thisdir->QUIC_state == QUIC_OPEN_SENT &&
                  hdr.header_form == 1 && hdr.packet_type == 1 &&
                  hdr.dcid_len > 0     && hdr.fixed_bit == 1   &&
                  hdr.dcid_len <= 20   && hdr.scid_len <= 20  )
            thisdir->pup->quic_zero_rtt+=1;
   
  }

  // Search SNI if in initial state or in first QUIC_MAX_SNI_PKT=10 packets
  if( (thisdir == &(thisdir->pup->c2s) ) && (
          (thisdir->QUIC_state == QUIC_UNKNOWN) ||  
          (thisdir->QUIC_state == QUIC_OPEN_SENT) ||
          ( thisdir->packets <= QUIC_MAX_SNI_PKT ) )
    ){

        if (hdr.packet_type == 0)
            search_QUIC_client_hello(thisdir, base + 8, &hdr);
        search_QUIC_SNI(thisdir);
  }

  if (thisdir->is_QUIC==1 && otherdir->is_QUIC==1)
   {
     if (thisdir->type==UDP_UNKNOWN ||
    	 thisdir->type==FIRST_RTP_PLUS || 
    	 thisdir->type==FIRST_RTP || 
    	 thisdir->type==FIRST_RTCP)
      { thisdir->type=UDP_QUIC; }
     else
      { 
        // fprintf(fp_stderr, "QUIC type overriding %d\n",thisdir->type);
    	thisdir->type=UDP_QUIC; 
      }

     if (otherdir->type==UDP_UNKNOWN ||
    	 otherdir->type==FIRST_RTP_PLUS || 
    	 otherdir->type==FIRST_RTP || 
    	 otherdir->type==FIRST_RTCP)
      { otherdir->type=UDP_QUIC; }
     else
      { 
        // fprintf(fp_stderr, "QUIC type overriding %d\n",otherdir->type);
    	otherdir->type=UDP_QUIC; 
      }
   }
  return;
}


void
udpL7_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
		 int dir, void *hdr, void *plast)
{
  udp_pair *pup = ((ucb *) pdir)->pup;
  ucb *thisdir, *otherdir;

  udpL7_dpi (pproto, (ucb *) pdir, hdr, plast);

  if (dir == C2S)
    {
      thisdir = &pup->c2s;
      otherdir = &pup->s2c;
    }
  else
    {
      thisdir = &pup->s2c;
      otherdir = &pup->c2s;
    }

  if (pup->packets < MAX_UDP_QUIC)
    check_QUIC (pip, (struct udphdr *) pproto, plast, thisdir, otherdir);
}

/* Map the UDP classification to the L7 types used by histograms */
int
udp_to_L7type (ucb *thisflow)
{
  switch (thisflow->type)
    {
    case RTP:
      return L7_FLOW_RTP;

    case RTCP:
      return L7_FLOW_RTCP;

    case RTP_PLUS:
      if ((thisflow->multiplexed_protocols & RFC7983_RTP) == 1)
	/* At least one subflow is RTP, possible to have RTCP subflows */
	return L7_FLOW_RTP;
      else if ((thisflow->multiplexed_protocols & RFC7983_RTCP) == 1)
	/* At least one RTCP subflow, no RTP subflows */
	return L7_FLOW_RTCP;
      else if ((thisflow->multiplexed_protocols & RFC7983_DTLS) == 1)
	/* Should not be possible, but just in case */
	return L7_FLOW_DTLS;
      else
	return L7_FLOW_UNKNOWN;

    case DNS:
      return L7_FLOW_DNS;

    case UDP_DTLS:
      return L7_FLOW_DTLS;

    case UDP_QUIC:
      return L7_FLOW_QUIC;

    case UDP_MTURN:
      return L7_FLOW_MTURN;

    default:
      return L7_FLOW_UNKNOWN;
    }
}

static void
udp_L7_histo (udp_pair *thisflow, ucb *thisdir, int dir)
{
  int L7type = udp_to_L7type (thisdir);

  switch (in_out_loc (thisflow->internal_src, thisflow->internal_dst, dir))
    {
    case OUT_FLOW:
      add_histo (L7_UDP_num_out, L7type);
      break;
    case IN_FLOW:
      add_histo (L7_UDP_num_in, L7type);
      break;
    case LOC_FLOW:
      add_histo (L7_UDP_num_loc, L7type);
      break;
    }
}

static void
udp_log_half_flow (udp_pair *pup, ucb *thisdir, Bool src)
{
  ipaddr addr = src ? pup->addr_pair.a_address : pup->addr_pair.b_address;
  portnum port = src ? pup->addr_pair.a_port : pup->addr_pair.b_port;
  Bool crypto = src ? pup->crypto_src : pup->crypto_dst;

  /* Address and port */
  wfprintf (fp_udp_logc, "%s %s",
	    crypto ? HostNameEncrypted (addr) : HostName (addr),
	    ServiceName (port));

  /* Flow start time [ms], duration [s], bytes and packets */
  wfprintf (fp_udp_logc, " %f %.6f %llu %lld",
	    time2double (thisdir->first_pkt_time) / 1000.,
	    elapsed (thisdir->first_pkt_time, thisdir->last_pkt_time) /
	    1000.0 / 1000.0, thisdir->data_bytes, thisdir->packets);

  /* Internal, crypto and UDP type */
  wfprintf (fp_udp_logc, " %d %d %d",
	    src ? pup->internal_src : pup->internal_dst, crypto,
	    thisdir->type);
}

/* Called by the plugin engine when a UDP flow is closed */
void
make_udpL7_conn_stats (void *flow, int tproto)
{
  udp_pair *thisflow = (udp_pair *) flow;
  ucb *thisC2S = &(thisflow->c2s);
  ucb *thisS2C = &(thisflow->s2c);

  if (tproto == PROTOCOL_TCP)
    return;

  /* RTP and RTCP flows are accounted by the RTP plugin */
  if (thisC2S->type != RTP && thisC2S->type != RTCP &&
      thisS2C->type != RTP && thisS2C->type != RTCP)
    {
      udp_L7_histo (thisflow, thisC2S, C2S);
      if (thisS2C->packets != 0)
	udp_L7_histo (thisflow, thisS2C, S2C);
    }

  if (!LOG_IS_ENABLED (LOG_UDP_COMPLETE) || fp_udp_logc == NULL)
    return;

  /* Client (columns 1-9) and server (columns 10-18) */
  udp_log_half_flow (thisflow, thisC2S, TRUE);
  wfprintf (fp_udp_logc, " ");
  udp_log_half_flow (thisflow, thisS2C, FALSE);

  /* DNS name */
  wfprintf (fp_udp_logc, " %s",
	    thisflow->dns_name != NULL ? StringEncryptedBase64 (thisflow->dns_name) : "-");

  /* QUIC details */
  wfprintf (fp_udp_logc, " %s",
	    thisflow->quic_sni_name != NULL ? StringEncryptedBase64 (thisflow->quic_sni_name) : "-");
  wfprintf (fp_udp_logc, " %s",
	    thisflow->quic_ua_string != NULL ? StringEncryptedBase64 (thisflow->quic_ua_string) : "-");

  if (thisflow->c2s.is_QUIC == 1 && thisflow->s2c.is_QUIC == 1)
    {
      wfprintf (fp_udp_logc, " 0x%08x", ntohl (*(uint32_t *) (thisflow->quic_c_vers)));
      wfprintf (fp_udp_logc, " 0x%08x", ntohl (*(uint32_t *) (thisflow->quic_s_vers)));
      wfprintf (fp_udp_logc, " %d", thisflow->quic_zero_rtt);
      wfprintf (fp_udp_logc, " %d", thisflow->quic_ech);
    }
  else
    wfprintf (fp_udp_logc, " - - 0 0");

#ifdef PACKET_STATS
  {
    int i;

     /* Segment sizes */
    wfprintf (fp_udp_logc, " %d",thisflow->c2s.seg_count);
    for (i=0;i<MAX_COUNT_SEGMENTS;i++) {
    	wfprintf (fp_udp_logc, " %d",thisflow->c2s.seg_size[i]);
     }

    wfprintf (fp_udp_logc, " %d",thisflow->s2c.seg_count);
    for (i=0;i<MAX_COUNT_SEGMENTS;i++) {
    	wfprintf (fp_udp_logc, " %d",thisflow->s2c.seg_size[i]);
     }

     /* Segment intertimes */
    for (i=0;i<MAX_COUNT_SEGMENTS-1;i++) {
    	wfprintf (fp_udp_logc, " %f",thisflow->c2s.seg_intertime[i]/1000.);
     }

    for (i=0;i<MAX_COUNT_SEGMENTS-1;i++) {
    	wfprintf (fp_udp_logc, " %f",thisflow->s2c.seg_intertime[i]/1000.);
     }

#define MEAN(SUM,ENNE) (((ENNE)>0)?((SUM)*1.0/(ENNE)):0.0)
#define VAR(ME,SQ,ENNE) (((ENNE)>1)?((SQ)-(ENNE)*(ME)*(ME))/((ENNE)-1):0.0)

    /* Averages */
     {
       double mval,varval;
       mval = MEAN(thisflow->c2s.data_bytes,thisflow->c2s.packets);
       varval = VAR(mval,thisflow->c2s.data_pkts_sum2,thisflow->c2s.packets);
       wfprintf (fp_udp_logc, " %d %f %f",thisflow->c2s.packets,mval,sqrt(varval));

       mval = MEAN(thisflow->s2c.data_bytes,thisflow->s2c.packets);
       varval = VAR(mval,thisflow->s2c.data_pkts_sum2,thisflow->s2c.packets);
       wfprintf (fp_udp_logc, " %d %f %f",thisflow->s2c.packets,mval,sqrt(varval));

       mval = MEAN(thisflow->c2s.seg_intertime_sum,thisflow->c2s.seg_count-1);
       varval = VAR(mval,thisflow->c2s.seg_intertime_sum2,thisflow->c2s.seg_count-1);
       wfprintf (fp_udp_logc, " %d",(thisflow->c2s.seg_count>1)?thisflow->c2s.seg_count:0);
       wfprintf (fp_udp_logc, " %f %f",mval/1e3,sqrt(varval)/1e3);

       mval = MEAN(thisflow->s2c.seg_intertime_sum,thisflow->s2c.seg_count-1);
       varval = VAR(mval,thisflow->s2c.seg_intertime_sum2,thisflow->s2c.seg_count-1);
       wfprintf (fp_udp_logc, " %d",(thisflow->s2c.seg_count>1)?thisflow->s2c.seg_count:0);
       wfprintf (fp_udp_logc, " %f %f",mval/1e3,sqrt(varval)/1e3);

     }
  }
#endif

  wfprintf (fp_udp_logc, "\n");
}
