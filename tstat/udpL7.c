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

#define ntohll(x) ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32)

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
  uint8_t token_len        ;
  uint64_t pkt_len         ;
  uint8_t pkt_len_len      ;
} quic_hdr;


/* Read Variable Length Integers
   As Defined in: RFC 9000, Section 16
   Input: start
   Output: result, offset (in Bytes)
*/
static uint64_t read_var_len_int(uint8_t * start, uint8_t * offset){

    uint8_t type =  *(start) >> 6;
    uint64_t result;
    if (type==0x00){
        result = *( (uint8_t*)(start) )& 0x3F;
        *offset = 1;
    }
    else if (type==0x01){
        result = ntohs(*( (uint16_t*)(start) )) & 0x3FFF;
        *offset = 2;
    }
    else if (type==0x02){
        result = ntohl(*( (uint32_t*)(start) )) & 0x3FFFFFFF;
        *offset = 4;
    }
    else if (type==0x03){
        result = ntohll(*( (uint64_t*)(start) )) & 0x3FFFFFFFFFFFFFFF;
        *offset = 16;
    }

    return result;

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

static void search_QUIC_client_hello(ucb * thisdir, unsigned char * data, int data_len, int payload_offset, quic_hdr hdr  ){
    
    /* Parameter payload_offset represents the starting of the payload if Packet Number is on 1 Byte
       It is update consequently after reading the packet number. */
    
    int err;
    EVP_CIPHER_CTX *ctx;
    int plaintext_len;
    unsigned char plaintext [QUIC_MAX_PKT];
    unsigned char client_hello [QUIC_MAX_ACCUL];
    int conn_id_len = hdr.dcid_len;
    // Check UDP packet long enough. Will read up to payload_offset + 3 B
    if (payload_offset+3 > data_len || payload_offset<19)
        return;
        
    // Get initial secrets [RFC 9001, Section 5.4.1]
    // Example in Appendix from https://datatracker.ietf.org/doc/html/rfc9001
    
    // The salt depends on the version. Must be updated in future versions
    const unsigned char *salt = quic_initial_salt(hdr.version);
    if (salt == NULL)
        return;

    /* HKDF-{Extract,Expand} Functions from TLS 1.3 [RFC 8446 Section 7.1 and RFC 5869 Section 2.2 and 2.3] */
    unsigned char initial_secret[SHA256HashSize];
    err = hkdfExtract(SHA256, salt, 20, thisdir->QUIC_conn_id, conn_id_len, initial_secret);
    if (err !=0)
      return;
    
    /* Client Initial Secret */
    static const char HkdfLabel_client_initial_secret[19] =
        {0x00, 0x20, 0x0F, 't', 'l', 's', '1', '3', ' ', 'c', 'l', 'i', 'e', 'n', 't', ' ', 'i', 'n', 0x00};
    unsigned char client_initial_secret[32];     
    err = hkdfExpand(SHA256, initial_secret, 32, HkdfLabel_client_initial_secret, 19,
                            client_initial_secret, 32);
    if (err !=0)
        return;

    //  Key
    static const char HkdfLabel_key[18] =
        {0x00, 0x10, 0x0E, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'k', 'e', 'y', 0x00};    
    unsigned char key[16];  
    err = hkdfExpand(SHA256, client_initial_secret, SHA256HashSize, HkdfLabel_key, 18,
                             key, 16);
    if (err !=0)
        return;

    // Initialization Vector
    static const char HkdfLabel_iv[17] =
        {0x00, 0x0C, 0x0D, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'i', 'v', 0x00};
        
    unsigned char iv[12];  
    err = hkdfExpand(SHA256, client_initial_secret, SHA256HashSize, HkdfLabel_iv, 17,
                             iv, 12);
    if (err !=0)
        return;

    // Header Protection
    static const char HkdfLabel_hp[17] =
        {0x00, 0x10, 0x0D, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'h', 'p', 0x00};
    unsigned char hp[16];  
    err = hkdfExpand(SHA256, client_initial_secret, SHA256HashSize, HkdfLabel_hp, 17,
                             hp, 16);
    if (err !=0)
        return;


    /* Mask obtained from encrypting first 16B with 'hp', but assuming 4B pkt len
      [RFC 9001, Section 5.4.1, 5.4.2, 5.4.3] */
    if (payload_offset+3 + 16 > data_len)
       return;
    
    EVP_CIPHER_CTX *ctx_mask;

    if (!(ctx_mask = EVP_CIPHER_CTX_new()))
        return;

    if (1 != EVP_EncryptInit_ex(ctx_mask, EVP_aes_128_cbc(), NULL, hp, 0)){
        EVP_CIPHER_CTX_free(ctx_mask);
        return;
    }

    int len = 0;
    if (1 != EVP_EncryptUpdate(ctx_mask, plaintext, &len, data+payload_offset+3, 16)){
        EVP_CIPHER_CTX_free(ctx_mask);
        return;
    }

    EVP_CIPHER_CTX_free(ctx_mask);
    
    /* Paccket numbers on 1, 2, 3 or 4B. Length of the Packet Number field is encrypted
       Using header protecion [RFC 9001, Section 5.4.1] */
    uint32_t pkn;
    uint8_t packet_nb_len_decripted = hdr.packet_nb_len ^ (plaintext[0] & 0x03);
    void * pkn_nb_ptr = data+payload_offset-1 ;
    if (packet_nb_len_decripted == 0) { // 0 -> 1B
        pkn = *((uint8_t*)(pkn_nb_ptr)) ^ plaintext[1]; 
    }
    else if (packet_nb_len_decripted == 1) { // 1 -> 2B
        pkn = ntohs ( *((uint16_t*)(pkn_nb_ptr))  ^  *((uint16_t*)(plaintext+1)) ); 
        payload_offset += 1; // Increase by 1 start of payload as pkn is 2B
    }
    else if (packet_nb_len_decripted == 2) { // 2 -> 3B
        pkn = *((uint32_t*)(pkn_nb_ptr));
        uint32_t plaintext_24b = *((uint32_t*)(plaintext+1));
        pkn = ntohl((pkn ^ plaintext_24b) & 0x00FFFFFF) >> 8 ; 
        payload_offset += 2; // Increase by 2 start of payload as pkn is 3B
    }
    else if (packet_nb_len_decripted == 3) { // 3 -> 4B
        pkn = ntohl ( *((uint32_t*)(pkn_nb_ptr))  ^  *((uint32_t*)(plaintext+1)) ) ; 
        payload_offset += 3; // Increase by 3 start of payload as pkn is 4B
    }

    /* Make XOR of packet numbe [RFC 9001, Section 5.3, paragraph 5 ]
       or https://github.com/NanXiao/code-for-my-blog/blob/master/2020/09/quic_server_initial/main.c */
    //iv[11] = iv[11] ^ pkn; // works only for 1B pkt nb  
    *(uint32_t*) (iv + 8) =  *(uint32_t*) (iv + 8) ^ htonl(pkn);

    /* Decrypt Payload */
    /* Sample code: https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption*/  
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return;
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv)){
        EVP_CIPHER_CTX_free(ctx);
        return;
    }  
    if(!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, data+payload_offset, data_len - payload_offset)){ 
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    // Process plain text
    unsigned char * ptr = &plaintext[0];
    int iterations = 0;

    // Pre fill in case is not the first packet
    if (thisdir->pup->quic_client_hello != NULL)
        memcpy(client_hello, thisdir->pup->quic_client_hello, thisdir->pup->quic_client_hello_len);
    else 
        memset(client_hello, 0xFF, QUIC_MAX_ACCUL); /*Set buffer to one */

    /* Accumulate fragments in CRYPTO messages */
    while (ptr < plaintext + plaintext_len - 16 && ptr >= plaintext && iterations <= QUIC_MAX_PKT &&
           ptr < plaintext + hdr.pkt_len -18 ){
        iterations ++; /* Avoid infinite loops */
        if ( *ptr == 0x01 || *ptr == 0x00)// PING or PADDING
            ptr++;

        else if ( *ptr == 0x06 ){ //CRYPTO
            uint8_t delta = 0;
            uint8_t delta_tot = 0;
            uint64_t offset = read_var_len_int(ptr + 1 + delta_tot, &delta);
            delta_tot += delta ;
            uint64_t length = read_var_len_int(ptr + 1 + delta_tot, &delta);

            delta_tot += delta ;
            if ((ptr + 1 + delta_tot + length > plaintext + plaintext_len) ||
                (offset + length > QUIC_MAX_ACCUL))
               break;
            memcpy( client_hello + offset, ptr + 1 + delta_tot, length);
            ptr=ptr + 1 + delta_tot+length;
        }
        else{ // UNKNOWN FRAME
          break;
        }
    }
    
    /* Set the length of read bytes to QUIC_MAX_ACCUL */        
    thisdir->pup->quic_client_hello_len = QUIC_MAX_ACCUL;
    
    /* Allocate the memory it it is the first packet */  
    if (thisdir->pup->quic_client_hello == NULL){
        thisdir->pup->quic_client_hello = malloc (thisdir->pup->quic_client_hello_len);
        if (thisdir->pup->quic_client_hello == NULL)
          return;
    }
    
    /* Copy in the pup's field  */  
    memcpy(thisdir->pup->quic_client_hello, client_hello,thisdir->pup->quic_client_hello_len);                

}

static void search_QUIC_SNI(ucb *thisdir){
                
    // Parsing TLC Client Hello. Inspired from tcpL7.c
    int idx = 38; // Was 43 in tcpL7.c, but need to subtract 5
    char * client_hello = thisdir->pup->quic_client_hello;
    int max_length = thisdir->pup->quic_client_hello_len;
                
    // Add session length = 1st byte of cipher suite section
    if (idx > max_length) 
      return;
    
    idx += 1 + client_hello[idx];

    // Add length of cipher suite section = 1st byte of compression section
    if (idx + 2 > max_length) 
      return;
    
    idx += 2 + ntohs(*(tt_uint16 *)(client_hello+idx)); 

    // Add length of compression section = 1st byte of extensions section
    if (idx > max_length)
      return;
    
    idx += 1 + client_hello[idx];

    // Full extensions section length
    if (idx + 2 > max_length) 
      return;
    
    int all_ext_len = ntohs(*(tt_uint16 *)(client_hello+idx));
    if (all_ext_len < 0)
      return;
    
    idx += 2; 

    // From tcpL7.c
    int ii = 0;   // pointer within the current extension
    int next = 0;
    char cname[81];
    int ext_type, ext_len, name_len, j, this_ii;
    int iterations;

    while (ii < all_ext_len && idx+ii < max_length){
        // extract extension type
        if (idx+ii+2 > max_length) 
          return;
        ext_type = ntohs(*(tt_uint16 *)(client_hello+idx+ii));
        ii += 2;

        // extract extension length
        if (idx + ii + 2 > max_length) 
          return;
        ext_len = ntohs(*(tt_uint16 *)(client_hello + idx + ii));
        if (ext_len < 0)
          return;
        ii += 2;

        switch (ext_type)
         {
            // SNI (Server Name Indication)
            case 0x0000:

                // extension length
                if (idx+ii+2 > max_length) 
                  return;
                next = ii + ext_len;

                // skip up to the 1st byte of "Server Name"
                ii += 3;
                if (idx+ii+2 > max_length) 
                  return;
                name_len = ntohs(*(tt_uint16 *)(client_hello+idx+ii));
                ii += 2;

                // copy server name
                if (idx+ii > max_length) 
                  return;
                for (j=0; j < name_len && j < 79 && idx+ii+j < max_length; j++)
                 {
                    cname[j]=client_hello[idx+ii+j];
                 }
                cname[j]='\0';

                // Check if length do not match (could have read truncated SNI)
                if ( strlen(cname) != name_len )
                    return;

                // crosscheck that subject has a reasonable syntax
                if (regexec(&re_ssl_subject,cname, (size_t) 0, NULL, 0)==0)
                {
                  if (regexec(&re_ssl_clean,cname, (size_t) 0, NULL, 0)==0)

                    if (thisdir->pup->quic_sni_name==NULL){
                      thisdir->pup->quic_sni_name = url_encode(cname);
                      //printf("%s\n", thisdir->pup->quic_sni_name);
                    }
                }

                ii = next;
                break;
            // QUIC transport parameters. Obsolete, works only for Google QUIC */
            case 0x0039:
                this_ii = ii;
                iterations = 0;
                while(this_ii < ii + ext_len && this_ii>=0 && iterations <= QUIC_MAX_PKT){
                    
                    // Read Type and Len
                    uint8_t offset = 0;
                    uint8_t offset_tot = 0;
                    if (idx+this_ii+offset_tot + 4 > max_length )
                      return;
                    uint64_t param_type = read_var_len_int(client_hello+idx+this_ii+offset_tot, &offset);
                    offset_tot +=offset;
                    if (idx+this_ii+offset_tot + 4 > max_length)
                      return;
                    uint64_t param_len =  read_var_len_int(client_hello+idx+this_ii+offset_tot, &offset);
                    offset_tot +=offset;

                    // Find Google User Agent
                    if (param_type == 0x3129){
                        if (idx+this_ii+offset_tot + param_len > max_length && idx+this_ii+offset_tot + param_len >= 0)
                          return;
                        memcpy(cname, client_hello+idx+this_ii+offset_tot, min(80, param_len));
                        cname[min(80, param_len)]='\0';
                        if (thisdir->pup->quic_ua_string==NULL)
                            thisdir->pup->quic_ua_string = url_encode(cname);
                    }
                    this_ii += offset_tot + param_len;
                    iterations ++;
                }

                ii += ext_len;
                break;
            case 0xfe0d: // = 65037 
            /* From https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml */

                thisdir->pup->quic_ech=ext_len;
                ii += ext_len;
                break;
            default:
                ii += ext_len;
                break;
         }
     }

    return;                     
}


static quic_hdr parse_quic_hdr (unsigned char *base, int data_len){

    quic_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));

    /* Notice: The four least significant bits of the first byte are protected for packets with long headers;
    the five least significant bits of the first byte are protected for packets with short headers. 
    [RFC 9001, Section 5.4]*/
    
    if (data_len<=5)
      return hdr;

    hdr.header_form = (base[0] >> 7) & 1;
    hdr.fixed_bit = (base[0] >> 6) & 1;

    if (hdr.header_form == 1){ // Long Packet
        hdr.packet_type = (base[0] >> 4) & 0x03;
        hdr.reserved = (base[0] >> 2) & 0x03;
        hdr.packet_nb_len = base[0] & 0x03; /* Notice: it is encrypted */
        memcpy(hdr.version, base + 1, 4);

        hdr.dcid_len = base[5];
        if ((hdr.dcid_len > 20) || (5 + 1 + hdr.dcid_len >= data_len))
          return hdr;
        memcpy(hdr.dcid, base + 5 + 1, hdr.dcid_len);

        hdr.scid_len = base[5 + 1 + hdr.dcid_len];
        if ((hdr.scid_len > 20) || (5 + 1 + hdr.dcid_len + 1 + hdr.scid_len >= data_len))
          return hdr;
        memcpy(hdr.scid, base + 5 + 1 + hdr.dcid_len + 1, hdr.scid_len);
        
        // Search token and len only in initial packets
        if (hdr.packet_type == 0){
            unsigned char * ptr = base + 5 + 1 + hdr.dcid_len + 1 + hdr.scid_len;
            uint8_t token_len_len = 0;
            if ((ptr + 4 >= base + data_len) || (ptr < base))
              return hdr;
            uint64_t token_len = read_var_len_int(ptr, &token_len_len);
            
            // Include in the token_len field both token len size and token size
            hdr.token_len = token_len_len + token_len;
            uint8_t pkt_len_len = 0;
            ptr += token_len_len + token_len;
            if ((ptr + 4 >= base + data_len) || (ptr < base))
              return hdr;
            hdr.pkt_len = read_var_len_int(ptr, &pkt_len_len);
            hdr.pkt_len_len = pkt_len_len;
        }
    }
    else // Short Packet
      hdr.spin_bit = (base[0] >> 5) & 1;

    return hdr;
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

  if (data_len < 27 || payload_len == 0)
    return;  /* Minimum safe QUIC size is probably 8+19 bytes */


  /* New code for Google QUIC Version >= 46 (QUIC IETF) */
  if( (thisdir->QUIC_state == QUIC_UNKNOWN) ||  (thisdir->QUIC_state == QUIC_OPEN_SENT) ){
        /* MATCHING QUIC IETF
           We only have part of the header in clear.
           We match the DCID with SCID and version across "Initial" (or "0-RTT") packets */

        quic_hdr hdr;
        hdr = parse_quic_hdr(base + 8, data_len - 8);

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
            // Search 0-RTT
            unsigned char * ptr_next = base + 17 +
                                       hdr.dcid_len + hdr.scid_len + hdr.token_len + hdr.pkt_len;
            if (ptr_next + 5 < base + data_len ){
                quic_hdr hdr_second = parse_quic_hdr(ptr_next, 5);
                if (hdr_second.packet_type == 1)
                    thisdir->pup->quic_zero_rtt+=1;
            }    
                    
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

        quic_hdr hdr;
        hdr = parse_quic_hdr(base + 8, data_len - 8);
        search_QUIC_client_hello(thisdir, base, data_len,
                                 16 + hdr.dcid_len + hdr.scid_len + hdr.token_len + hdr.pkt_len_len, hdr );
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
