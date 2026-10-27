/*
 *
 * Copyright (c) 2001
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
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/


/*
 * ipv6.h:
 *
 * Structures for IPv6 packets
 *
 */
#include <sys/types.h>
#include <netinet/icmp6.h>

/*
 * IPv6 datagram header 
 */
struct ipv6
{
  u_int ip6_ver_tc_flabel;	/* first 4  bits = version #, 
				   next  4  bits = Trafic class,
				   next  24 bits = flow label */
  u_short ip6_lngth;		/* Payload length */
  u_char ip6_nheader;		/* Next Header */
  u_char ip6_hlimit;		/* Hop Limit */
  struct in6_addr ip6_saddr;	/* Source Address */
  struct in6_addr ip6_daddr;	/* Destination Address */
};


/* IPv6 extension header format */
struct ipv6_ext
{
  u_char ip6ext_nheader;	/* Next Header */
  u_char ip6ext_len;		/* number of bytes in this header */
  u_char ip6ext_data[1];	/* optional data */
};


/* IPv6 fragmentation header */
struct ipv6_ext_frag
{
  u_char ip6ext_fr_nheader;	/* Next Header */
  u_char ip6ext_fr_res;		/* (reserved) */
  u_short ip6ext_fr_offset;	/* fragment offset(13),res(2),M(1) */
  u_long ip6ext_fr_ID;		/* ID field */
};


void IPv6_support (struct ip *pip, void * plast, int ip_direction);
void ICMPv6_support(char * next, int internal_srcv6, int internal_dstv6);
int LoadInternalNetsv6 (char *file, struct in6_addr *internal_net_listv6, int *internal_net_mask_size, int * tot_internal_nets);
int LoadCryptoNetsv6 (char *file, struct in6_addr *crypto_net_listv6, int *crypto_net_mask_size, int * tot_crypto_nets);
int internal_ipv6(struct in6_addr adx);
int crypto_ipv6(struct in6_addr adx);
char * findheader_ipv6 ( void *pplast,struct ip *pip,unsigned int * proto_type);
/* tcptrace's IPv6 access routines */
struct tcphdr *gettcp (struct ip *pip, void **pplast);
struct udphdr *getudp (struct ip *pip, void **pplast);
int gethdrlength (struct ip *pip, void *plast);
int getpayloadlength (struct ip *pip, void *plast);
