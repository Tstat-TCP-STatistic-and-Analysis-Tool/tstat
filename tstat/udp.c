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


#include "tstat.h"
#include "tcpL7.h"
#include "dns_cache.h"

extern Bool dns_enabled;

extern struct L3_bitrates L3_bitrate;
extern struct L4_bitrates L4_bitrate;

/* locally global variables */
static int packet_count = 0;
static int search_count = 0;


/* provided globals  */
int num_udp_pairs = -1;		/* how many pairs we've allocated */
u_long udp_trace_count = 0;
udp_pair **utp = NULL;		/* array of pointers to allocated pairs */


/* local routine definitions */
static udp_pair *NewUTP (struct ip *, struct udphdr *);
static udp_pair *FindUTP (struct ip *, struct udphdr *, int *);
void print_udp_periodic_log(udp_pair *);


extern unsigned long int fcount;
extern Bool warn_MAX_;
extern unsigned long int f_UDP_count;
extern FILE *fp_periodic_udp_logc;


static udp_pair *
NewUTP (struct ip *pip, struct udphdr *pudp)
{
  udp_pair *pup;
  int old_new_udp_pairs = num_udp_pairs;
  int steps = 0;

  /* look for the next eventually available free block */
  num_udp_pairs++;
  num_udp_pairs = num_udp_pairs % GLOBALS.Max_UDP_Pairs;
  /* make a new one, if possible */
  while ((num_udp_pairs != old_new_udp_pairs) && (utp[num_udp_pairs] != NULL)
	 && (steps < GLOBALS.List_Search_Dept))
    {
      steps++;
      /* look for the next one */
//         fprintf (fp_stdout, "%d %d\n", num_udp_pairs, old_new_udp_pairs);
      num_udp_pairs++;
      num_udp_pairs = num_udp_pairs % GLOBALS.Max_UDP_Pairs;
    }
  if (utp[num_udp_pairs] != NULL)
    {
      if (warn_MAX_)
	{
	  fprintf (fp_stderr, 
        "\nooopsss: number of simultaneous connection opened is greater then the maximum supported number!\n"
	    "you have to rebuild the source with a larger LIST_SEARCH_DEPT defined!\n"
	    "or possibly with a larger 'MAX_UDP_PAIRS' defined!\n");
	}
      warn_MAX_ = FALSE;
      return (NULL);
    }

  /* create a new UDP pair record and remember where you put it */
  pup = utp[num_udp_pairs] = utp_alloc ();

  /* grab the address from this packet */
  CopyAddr (&pup->addr_pair,
	    pip, ntohs (pudp->uh_sport), ntohs (pudp->uh_dport));

  pup->c2s.first_pkt_time.tv_sec = 0;
  pup->s2c.first_pkt_time.tv_sec = 0;

  pup->c2s.last_pkt_time.tv_sec = -1;
  pup->s2c.last_pkt_time.tv_sec = -1;

  pup->c2s.pup = pup;
  pup->s2c.pup = pup;

  pup->internal_src = internal_src;
  pup->internal_dst = internal_dst;

  if (crypto_src)
   {
     if (ADDR_ISV6(&(pup->addr_pair.a_address)))
       store_crypto_ipv6(&(pup->addr_pair.a_address.un.ip6));
     else
       store_crypto_ip(&(pup->addr_pair.a_address.un.ip4));
   }

  if (crypto_dst)
   {
     if (ADDR_ISV6(&(pup->addr_pair.a_address)))
       store_crypto_ipv6(&(pup->addr_pair.b_address.un.ip6));
     else
       store_crypto_ip(&(pup->addr_pair.b_address.un.ip4));
   }

  pup->crypto_src = crypto_src;
  pup->crypto_dst = crypto_dst;

  pup->c2s.type = UDP_UNKNOWN;
  pup->s2c.type = UDP_UNKNOWN;
  
  pup->c2s.QUIC_state = QUIC_UNKNOWN;
  pup->s2c.QUIC_state = QUIC_UNKNOWN;
  pup->c2s.is_QUIC = 0;
  pup->s2c.is_QUIC = 0;
  
 if (dns_enabled)
  {
    if (PIP_ISV6(pip))
     { 
    struct DNS_data_IPv6* dns_data =  get_dns_entry_ipv6(&(PIP_V6(pip)->ip6_saddr), &(PIP_V6(pip)->ip6_daddr));
    if(dns_data!=NULL){
	 pup->dns_name = dns_data->hostname;
	 pup->dns_server.addr_vers = 6;
	 memcpy((&pup->dns_server.un.ip6),&(dns_data->dns_server),sizeof(struct in6_addr));
	 pup->request_time = dns_data->request_time;
	 pup->response_time = dns_data->response_time;
	 pup->crypto_dns = crypto_ipv6(pup->dns_server.un.ip6);
     }
     }
    else
    {
    /* Do reverse lookup */
    struct DNS_data* dns_data = get_dns_entry(pip->ip_src.s_addr, pip->ip_dst.s_addr);
    if(dns_data!=NULL){
	  pup->dns_name = dns_data->hostname;
	  pup->dns_server.addr_vers = 4;
	  memcpy((&pup->dns_server.un.ip4),&(dns_data->dns_server),sizeof(struct in_addr));
	  pup->request_time = dns_data->request_time;
	  pup->response_time = dns_data->response_time;
	  pup->crypto_dns = crypto_ip(pup->dns_server.un.ip4);
     }
    }
  }
 else
  pup->dns_name = NULL;
//  pup->dns_name = reverse_lookup(ntohl(pip->ip_src.s_addr), ntohl(pip->ip_dst.s_addr));

  pup->quic_sni_name = NULL;
  pup->quic_ua_string = NULL;
  memset(pup->quic_c_vers, 0, 4);
  memset(pup->quic_s_vers, 0, 4);
  pup->quic_zero_rtt = 0;
  pup->quic_ech = 0;
  pup->quic_client_hello = NULL;
  pup->quic_client_hello_len = 0;
  pup->is_stun_initiated = 0;

  // LOG_PERIODIC
  pup->last_print_time = current_time;
  
  
  return (utp[num_udp_pairs]);
}


udp_pair **pup_hashtable;


/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
// static 
udp_pair *
FindUTP (struct ip * pip, struct udphdr * pudp, int *pdir)
{
  udp_pair **ppup_head = NULL;
  udp_pair *pup;
  udp_pair *pup_last;
  udp_pair tp_in;


  int dir;
  hash hval;

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip,
	    ntohs (pudp->uh_sport), ntohs (pudp->uh_dport));

  /* grab the hash value (already computed by CopyAddr) */
  hval = tp_in.addr_pair.hash % GLOBALS.Hash_Table_Size;


  pup_last = NULL;
  ppup_head = &pup_hashtable[hval];
  for (pup = *ppup_head; pup; pup = pup->next)
    {
      ++search_count;
      if (SameConn (&tp_in.addr_pair, &pup->addr_pair, &dir))
	{
	  /* move to head of access list (unless already there) */
	  if (pup != *ppup_head)
	    {
	      pup_last->next = pup->next;	/* unlink */
	      pup->next = *ppup_head;	/* move to head */
	      *ppup_head = pup;
	    }
	  *pdir = dir;
	  return (pup);
	}
      pup_last = pup;
    }

/* if is elapsed an IDLE_TIME from the last cleaning flow operation I will start
a new one */

  // we fire it at DOUBLE rate, but actually clean only those > UDP_IDLE_TIME
  if (elapsed (last_cleaned, current_time) > GLOBALS.GC_Fire_Time)
    {
      int i;
      for (i=0; i< elapsed (last_cleaned, current_time) / GLOBALS.GC_Fire_Time; i++ )
         trace_done_periodic ();
      last_cleaned = current_time;
    }

  fcount++;
  f_UDP_count++;
  add_histo (L4_flow_number, L4_FLOW_UDP);

  pup = NewUTP (pip, pudp);

  /* put at the head of the access list */
  if (pup)
    {
      tot_conn_UDP++;
      pup->next = *ppup_head;
      *ppup_head = pup;
    }

  *pdir = C2S;

  /*Return the new utp */

  return (pup);
}


void
udp_header_stat (struct udphdr * pudp, struct ip * pip, void *plast)
{
  int ip_len = gethdrlength (pip, plast) + getpayloadlength (pip, plast);

  if (internal_src && !internal_dst)
    {
      L4_bitrate.out[UDP_TYPE] += ip_len;
      L3_bitrate.out[PIP_ISV6(pip)?L3_IPv6_UDP:L3_IPv4_UDP] += ip_len;
      add_histo (udp_port_dst_out, (float) ntohs(pudp->uh_dport));
    }
  else if (!internal_src && internal_dst)
    {
      L4_bitrate.in[UDP_TYPE] += ip_len;
      L3_bitrate.in[PIP_ISV6(pip)?L3_IPv6_UDP:L3_IPv4_UDP] += ip_len;
      add_histo (udp_port_dst_in, (float) ntohs(pudp->uh_dport));
    }
  else if (internal_src && internal_dst)
    {
      L4_bitrate.loc[UDP_TYPE] += ip_len;
      L3_bitrate.loc[PIP_ISV6(pip)?L3_IPv6_UDP:L3_IPv4_UDP] += ip_len;
      add_histo (udp_port_dst_loc, (float) ntohs(pudp->uh_dport));
    }

  return;
}

int
udp_flow_stat (struct ip * pip, struct udphdr * pudp, void *plast)
{

  udp_pair *pup_save;
  ucb *thisdir;
  udp_pair tp_in;
  int dir;
  u_short uh_sport;		/* source port */
  u_short uh_dport;		/* destination port */
  u_short uh_ulen;		/* data length */
  int ip_len;

  /* make sure we have enough of the packet */
  if ((unsigned long) pudp + sizeof (struct udphdr) - 1 >
      (unsigned long) plast)
    {
      if (warn_printtrunc)
	fprintf (fp_stderr,
		 "UDP packet %lu truncated too short to trace, ignored\n",
		 pnum);
      ++ctrunc;
      return (FLOW_STAT_SHORT);
    }


  /* convert interesting fields to local byte order */
  uh_sport = ntohs (pudp->uh_sport);
  uh_dport = ntohs (pudp->uh_dport);
  uh_ulen = ntohs (pudp->uh_ulen);
  ip_len = gethdrlength (pip, plast) + getpayloadlength (pip, plast);

  /* stop at this level of analysis */
  ++udp_trace_count;

  /* make sure this is one of the connections we want */
  pup_save = FindUTP (pip, pudp, &dir);

  ++packet_count;

  /*MT/MMM: log periodic - Do this before updating counters*/
  if ( elapsed(pup_save->last_print_time, current_time) > GLOBALS.Log_Periodic_Interval) 
    {
      print_udp_periodic_log(pup_save);
   }
   
  if (pup_save == NULL)
    {
      return (FLOW_STAT_NULL);
    }

  /* do time stats */
  if (ZERO_TIME (&pup_save->first_time))
    {
      pup_save->first_time = current_time;

    }
  pup_save->last_time = current_time;

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip, uh_sport, uh_dport);

  /* figure out which direction this packet is going */
  if (dir == C2S)
    thisdir = &pup_save->c2s;
  else
    thisdir = &pup_save->s2c;


  if ((thisdir->last_pkt_time.tv_sec) == -1)	/* is the first time I see this flow */
    {
      /* destination port of the flow */
      add_histo (udp_port_flow_dst, (float) (ntohs (pudp->uh_dport)));
      /* flow starting time */
      thisdir->first_pkt_time = current_time;
    }
  thisdir->last_pkt_time = current_time;

  /* do data stats */
  thisdir->data_bytes += uh_ulen - 8;	/* remove the UDP header */
#ifdef PACKET_STATS
 {
  int udp_data_length;
  
      udp_data_length = (uh_ulen -8);
      thisdir->data_pkts_sum2 += udp_data_length*udp_data_length; 
      
      { double current_intertime;
      if (thisdir->seg_count==0)
       {
         thisdir->last_seg_time=time2double(current_time);
       }
      else
       {
         current_intertime = 
	      time2double(current_time) - thisdir->last_seg_time;
         thisdir->last_seg_time=time2double(current_time);
	 thisdir->seg_intertime_sum += current_intertime;
	 thisdir->seg_intertime_sum2 += current_intertime*current_intertime;
       }

      if (thisdir->seg_count<MAX_COUNT_SEGMENTS)
       {
         thisdir->seg_size[thisdir->seg_count] = udp_data_length;
	 if (thisdir->seg_count>0)
	  {
	    thisdir->seg_intertime[thisdir->seg_count-1] = current_intertime;
	  }
       }

	 thisdir->seg_count++;
      }
 }
#endif


  /* total packets stats */
  ++pup_save->packets;
  ++thisdir->packets;

  if (PIP_ISV4(pip))
   {
   /*TOPIX*/
    /*TTL stats */
     if ((thisdir->ttl_min == 0) || (thisdir->ttl_min > (int) pip->ip_ttl))
       thisdir->ttl_min = (int) pip->ip_ttl;
     if (thisdir->ttl_max < (int) pip->ip_ttl)
       thisdir->ttl_max = (int) pip->ip_ttl;
     thisdir->ttl_tot += (u_llong) pip->ip_ttl;
   }
  else
   {
   /*TOPIX*/
    /*TTL stats */
     if ((thisdir->ttl_min == 0) || (thisdir->ttl_min > (int) PIP_V6(pip)->ip6_hlimit))
       thisdir->ttl_min = (int) PIP_V6(pip)->ip6_hlimit;
     if (thisdir->ttl_max < (int) PIP_V6(pip)->ip6_hlimit)
       thisdir->ttl_max = (int) PIP_V6(pip)->ip6_hlimit;
     thisdir->ttl_tot += (u_llong) PIP_V6(pip)->ip6_hlimit;
   }
   /*TOPIX*/
    //
    // NOW, this should be called by proto_analyzer...
    //
    //   p_rtp = getrtp (pudp, plast);
    //   if ((p_rtp) != NULL)
    //       rtpdotrace (thisdir, p_rtp, dir, pip);
    // 
    // 

    proto_analyzer (pip, pudp, PROTOCOL_UDP, thisdir, dir, plast);

    //if (thisdir != NULL && thisdir->pup != NULL)
    make_udpL7_rate_stats(thisdir, ip_len);

  return (FLOW_STAT_OK);
}

void
udptrace_init (void)
{
  static Bool initted = FALSE;
  extern udp_pair **pup_hashtable;

  if (initted)
    return;

  initted = TRUE;

  /* initialize the hash table */

  pup_hashtable = (udp_pair **) MallocZ (GLOBALS.Hash_Table_Size * sizeof (udp_pair *));

  /* create an array to hold any pairs that we might create */
  utp = (udp_pair **) MallocZ (GLOBALS.Max_UDP_Pairs * sizeof (udp_pair *));
}

void
udptrace_done (void)
{
    udp_pair *pup;
    int ix;
    int dir = -1;

    for (ix = 0; ix < GLOBALS.Max_UDP_Pairs; ix++) {
        pup = utp[ix];
        // check if the flow has been already closed
        if (pup == NULL)
            continue;
        /* consider this udp connection */
            close_udp_flow(pup, ix, dir);
/*
        if (!con_cat) {
            //flush histos and call the garbage colletor
            //Note: close_udp_flow() calls make_udp_conn_stats()
            close_udp_flow(pup, ix, dir);
        }
        else
            //only flush histos
            make_udp_conn_stats (pup, TRUE);
*/
    }
}

void
make_udp_conn_stats (udp_pair * pup_save, Bool complete)
{
  double etime;

  if (complete)
    {
      if (pup_save->internal_src && !pup_save->internal_dst)
	{
	  add_histo (udp_cl_b_s_out, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_s_in, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_out, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_in, pup_save->s2c.data_bytes);

	  add_histo (udp_cl_p_out, pup_save->c2s.packets);
	  add_histo (udp_cl_p_in, pup_save->s2c.packets);
	}
      else if (!pup_save->internal_src && pup_save->internal_dst)
	{
	  add_histo (udp_cl_b_s_out, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_s_in, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_out, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_in, pup_save->c2s.data_bytes);

	  add_histo (udp_cl_p_out, pup_save->s2c.packets);
	  add_histo (udp_cl_p_in, pup_save->c2s.packets);
	}
      else if (pup_save->internal_src && pup_save->internal_dst)
	{
	  add_histo (udp_cl_b_s_loc, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_s_loc, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_loc, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_loc, pup_save->c2s.data_bytes);

	  add_histo (udp_cl_p_loc, pup_save->s2c.packets);
	  add_histo (udp_cl_p_loc, pup_save->c2s.packets);

	}
      else
	{
	  if (warn_IN_OUT)
	    {
	      fprintf (fp_stderr, 
            "\nWARN: This udp flow is neither incoming nor outgoing: src - %s;",
		    HostName (pup_save->addr_pair.a_address));
	      fprintf (fp_stderr, " dst - %s!\n",
		      HostName (pup_save->addr_pair.b_address));
	      warn_IN_OUT = FALSE;
	    }
	  return;
	}
    }
    
  print_udp_periodic_log(pup_save);
  
  /* Statistics using plugins */

  make_proto_stat (pup_save, PROTOCOL_UDP);

  /* connection time */
  /* from microseconds to ms */
  etime = elapsed (pup_save->first_time, pup_save->last_time);
  etime = etime / 1000;
  add_histo (udp_tot_time, etime);
}


void
close_udp_flow (udp_pair * pup, int ix, int dir)
{

  extern udp_pair **pup_hashtable;
  udp_pair **ppuph_head = NULL;
  udp_pair *puph_tmp, *puph, *puph_prev;
  unsigned int cleaned = 0;
  hash hval;
  int j;
  int tmp;

  /* must be cleaned */
  cleaned++;

  /* Consider this flow for statistic collections */
  make_udp_conn_stats (pup, TRUE);
  tot_conn_UDP--;

  /* free up hash element->.. */
  hval = pup->addr_pair.hash % GLOBALS.Hash_Table_Size;

  ppuph_head = &pup_hashtable[hval];
  j = 0;
  puph_prev = *ppuph_head;
  for (puph = *ppuph_head; puph; puph = puph->next)
    {
      j++;
      if (SameConn (&pup->addr_pair, &puph->addr_pair, &tmp))
	{
	  puph_tmp = puph;
	  if (j == 1)
	    {
	      /* it is the top of the list */
	      pup_hashtable[hval] = puph->next;
	    }
	  else
	    {
	      /* it is in the middle of the list */
	      puph_prev->next = puph->next;
	    }
	  utp_release (puph_tmp);
	  break;
	}
      puph_prev = puph;
    }

  if (ix == -1)			/* I should look for the correct ix value */
    {
      for (ix = 0; ix < GLOBALS.Max_UDP_Pairs; ++ix)
	{
	  //      pup = utp[ix];

	  if (utp[ix] == NULL)
	    continue;

	  if (SameConn (&pup->addr_pair, &utp[ix]->addr_pair, &tmp))
	    {
	      break;
	    }
	}
    }

  utp[ix] = NULL;

}

/* 
** Code to URLencode (percent-encode) a string. 
** Public domain code from http://www.geekhideout.com/urlcode.shtml
*/


/* Converts an integer value to its hex character*/
char to_hex(char code) 
{
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str)
{
  char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
  while (*pstr)
   {
     if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') 
       *pbuf++ = *pstr;
     else if (*pstr == ' ') 
       *pbuf++ = '+';
     else 
       *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
     pstr++;
   }
  *pbuf = '\0';
  return buf;
}

/* Returns a url-decoded version of str */

void print_udp_periodic_log(udp_pair * pup_save) {
  ucb *thisUdir,*thisC2S,*thisS2C;
  udp_pair *pup;
  
  thisC2S = &(pup_save->c2s);
  thisS2C = &(pup_save->s2c);

  if (!fp_periodic_udp_logc)
    return;

  thisUdir = thisC2S;
  pup = thisUdir->pup;

  //     #   Field Meaning
  //    --------------------------------------
  //     1   Source Address
  //     2   Source Port

  if (pup->crypto_src==FALSE)
     wfprintf (fp_periodic_udp_logc, "%s %s",
	       HostName (pup->addr_pair.a_address),
	       ServiceName (pup->addr_pair.a_port));
  else 
     wfprintf (fp_periodic_udp_logc, "%s %s",
	       HostNameEncrypted (pup->addr_pair.a_address),
	       ServiceName (pup->addr_pair.a_port));
	       
/*
  //     3   Flow Start Time
  //     4   Flow Elapsed Time [s]
  //     5   Flow Size [Bytes]
  wfprintf (fp_periodic_udp_logc,
	   " %f %.6f %llu",
	   time2double ((thisUdir->first_pkt_time))/1000., 
//         elapsed (first_packet,thisUdir->first_pkt_time)/1000,
	   elapsed (thisUdir->first_pkt_time, thisUdir->last_pkt_time) /
	   1000.0 / 1000.0, thisUdir->data_bytes);

  //     6   No. of Total flow packets
  wfprintf (fp_periodic_udp_logc, " %lld", thisUdir->packets);
*/
  // 7 internal address
  // 8 udp_type

  wfprintf (fp_periodic_udp_logc, " %d %d",
	   pup_save->internal_src, pup_save->crypto_src);

  thisUdir = thisS2C;
  pup = thisUdir->pup;

  //     #   Field Meaning
  //    --------------------------------------
  //     9   Source Address
  //     10   Source Port

  if (pup->crypto_dst==FALSE)
     wfprintf (fp_periodic_udp_logc, " %s %s",
	       HostName (pup->addr_pair.b_address),
	       ServiceName (pup->addr_pair.b_port));
  else
     wfprintf (fp_periodic_udp_logc, " %s %s",
	       HostNameEncrypted (pup->addr_pair.b_address),
	       ServiceName (pup->addr_pair.b_port));
/*
  //     11   Flow Start Time
  //     12   Flow Elapsed Time [s]
  //     13   Flow Size [Bytes]
  wfprintf (fp_periodic_udp_logc,
	   " %f %.6f %llu",
	   time2double ((thisUdir->first_pkt_time))/1000., 
//         elapsed (first_packet,thisUdir->first_pkt_time)/1000,
	   elapsed (thisUdir->first_pkt_time, thisUdir->last_pkt_time) /
	   1000.0 / 1000.0, thisUdir->data_bytes);

  //     14   No. of Total flow packets
  wfprintf (fp_periodic_udp_logc, " %lld", thisUdir->packets);
*/
  // 15 internal address
  // 16 udp_type

  wfprintf (fp_periodic_udp_logc, " %d %d",
	   pup_save->internal_dst, pup_save->crypto_dst);

    /* TIME */

    wfprintf (fp_periodic_udp_logc, " %f %f %f %f",
              time2double(pup_save->last_print_time)/1000.0,
              elapsed(pup_save->first_time, pup_save->last_print_time)/1000.0,
              elapsed(pup_save->first_time, pup_save->last_time)/1000.0,
              elapsed(pup_save->last_print_time, pup_save->last_time)/1000.0
             );

    /* Packets and bytes*/

    wfprintf (fp_periodic_udp_logc,
              " %lu %lu",
              pup_save->c2s.packets - pup_save->last_print_c2s.packets,
              pup_save->c2s.data_bytes - pup_save->last_print_c2s.data_bytes);

    wfprintf (fp_periodic_udp_logc,
              " %lu %lu",
              pup_save->s2c.packets - pup_save->last_print_s2c.packets,
              pup_save->s2c.data_bytes - pup_save->last_print_s2c.data_bytes);
  
  
  wfprintf (fp_periodic_udp_logc, "\n");

  /*update counters*/
  pup_save->last_print_time = current_time; //ptp_save->last_time;
  pup_save->last_print_c2s = pup_save->c2s;
  pup_save->last_print_s2c = pup_save->s2c;
  
  return;
 
}


