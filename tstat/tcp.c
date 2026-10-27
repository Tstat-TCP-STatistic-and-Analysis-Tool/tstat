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

/* DNS cache piece */
#include "dns_cache.h"
long int tcp_cleaned = 0;
long int udp_cleaned = 0;

/* provided globals  */
extern FILE *fp_logc;
extern FILE *fp_lognc;
extern FILE *fp_rtp_logc;
extern FILE *fp_periodic_logc;

extern Bool is_stdin;
extern Bool printticks;
extern unsigned long int fcount;
extern unsigned long int f_TCP_count;
/* TOPIX */
extern unsigned long int f_RTP_tunneled_TCP_count;
extern struct L3_bitrates L3_bitrate;
extern struct L4_bitrates L4_bitrate;
/* end TOPIX */
extern int log_level;

extern long int tcp_packet_count;
extern Bool strict_privacy;

extern Bool dns_enabled;

/* garbage offloading vars */
int tcp_index = 0;
int udp_index = 0;

/* tcp database stats */
long not_id_p;
int search_count = 0;

int num_tcp_pairs = 0;		/* how many pairs we've allocated */
tcp_pair **ttp = NULL;		/* array of pointers to allocated pairs */
u_long tcp_trace_count_outgoing = 0;
u_long tcp_trace_count_incoming = 0;
u_long tcp_trace_count_local = 0;


/* local routine definitions */
static tcp_pair **NewTTP_2 (struct ip *, struct tcphdr *);
static ptp_snap **FindTTP (struct ip *, struct tcphdr *, int *);
static void free_tp (tcp_pair * ptp_save);
static int ConnReset (tcp_pair *);
static int ConnComplete (tcp_pair *);
void print_periodic_log(tcp_pair * ptp_save);
/*
static u_int SynCount (tcp_pair * ptp);
*/
/*
static u_int FinCount (tcp_pair * ptp);
*/


void
tcp_header_stat (struct tcphdr *ptcp, struct ip *pip, void *plast)
{
  int ip_len = gethdrlength (pip, plast) + getpayloadlength (pip, plast);
  
  /* perform TCP packet analysis */
  if ((!ACK_SET (ptcp) && SYN_SET (ptcp)))
    {
      if (internal_src && !internal_dst)
	{
	  add_histo (tcp_port_synsrc_out, (float) ntohs (ptcp->th_sport));
	  add_histo (tcp_port_syndst_out, (float) ntohs (ptcp->th_dport));
	}
      else if (!internal_src && internal_dst)
	{
	  add_histo (tcp_port_synsrc_in, (float) ntohs (ptcp->th_sport));
	  add_histo (tcp_port_syndst_in, (float) ntohs (ptcp->th_dport));
	}
      else if (internal_src && internal_dst)
	{
	  add_histo (tcp_port_synsrc_loc, (float) ntohs (ptcp->th_sport));
	  add_histo (tcp_port_syndst_loc, (float) ntohs (ptcp->th_dport));
	}
    }

  if (internal_src && !internal_dst)
    {
      L4_bitrate.out[TCP_TYPE] += ip_len;
      L3_bitrate.out[PIP_ISV6(pip)?L3_IPv6_TCP:L3_IPv4_TCP] += ip_len;
      add_histo (tcp_port_src_out, (float) ntohs (ptcp->th_sport));
      add_histo (tcp_port_dst_out, (float) ntohs (ptcp->th_dport));
    }
  else if (!internal_src && internal_dst)
    {
      L4_bitrate.in[TCP_TYPE] += ip_len;
      L3_bitrate.in[PIP_ISV6(pip)?L3_IPv6_TCP:L3_IPv4_TCP] += ip_len;
      add_histo (tcp_port_src_in, (float) ntohs (ptcp->th_sport));
      add_histo (tcp_port_dst_in, (float) ntohs (ptcp->th_dport));
    }
  else if (internal_src && internal_dst)
    {
      L4_bitrate.loc[TCP_TYPE] += ip_len;
      L3_bitrate.loc[PIP_ISV6(pip)?L3_IPv6_TCP:L3_IPv4_TCP] += ip_len;
      add_histo (tcp_port_src_loc, (float) ntohs (ptcp->th_sport));
      add_histo (tcp_port_dst_loc, (float) ntohs (ptcp->th_dport));
    }

  return;
}

/*
u_int
SynCount (tcp_pair * ptp)
{
  tcb *pab = &ptp->c2s;
  tcb *pba = &ptp->s2c;

  return (((pab->syn_count >= 1) ? 1 : 0) + ((pba->syn_count >= 1) ? 1 : 0));
}
*/

/*
u_int
FinCount (tcp_pair * ptp)
{
  tcb *pab = &ptp->c2s;
  tcb *pba = &ptp->s2c;

  return (((pab->fin_count >= 1) ? 1 : 0) + ((pba->fin_count >= 1) ? 1 : 0));
}
*/


/* copy the IP addresses and port numbers into an addrblock structure	*/
/* in addition to copying the address, we also create a HASH value	*/
/* which is based on BOTH IP addresses and port numbers.  It allows	*/
/* faster comparisons most of the time					*/
void
CopyAddr (tcp_pair_addrblock * ptpa,
	  struct ip *pip, portnum port1, portnum port2)
{
  ptpa->a_port = port1;
  ptpa->b_port = port2;

  if (PIP_ISV4 (pip))
    {				/* V4 */
      IP_COPYADDR (&ptpa->a_address, *IPV4ADDR2ADDR (&pip->ip_src));
      IP_COPYADDR (&ptpa->b_address, *IPV4ADDR2ADDR (&pip->ip_dst));
      /* fill in the hashed address */
      ptpa->hash = ptpa->a_address.un.ip4.s_addr
	+ ptpa->b_address.un.ip4.s_addr + ptpa->a_port + ptpa->b_port;
    }
  else
    {				/* V6 */
      int i;
      struct ipv6 *pip6 = (struct ipv6 *) pip;
      IP_COPYADDR (&ptpa->a_address, *IPV6ADDR2ADDR (&pip6->ip6_saddr));
      IP_COPYADDR (&ptpa->b_address, *IPV6ADDR2ADDR (&pip6->ip6_daddr));
      /* fill in the hashed address */
      ptpa->hash = ptpa->a_port + ptpa->b_port;
      for (i = 0; i < 16; ++i)
	{
	  ptpa->hash += ptpa->a_address.un.ip6.s6_addr[i];
	  ptpa->hash += ptpa->b_address.un.ip6.s6_addr[i];
	}
    }
}


int
WhichDir (tcp_pair_addrblock * ptpa1, tcp_pair_addrblock * ptpa2)
{

  /* same as first packet */
  if (IP_SAMEADDR (ptpa1->a_address, ptpa2->a_address) &&
      IP_SAMEADDR (ptpa1->b_address, ptpa2->b_address) &&
      (ptpa1->a_port == ptpa2->a_port) && (ptpa1->b_port == ptpa2->b_port))
    return (C2S);

  /* reverse of first packet */
  if (IP_SAMEADDR (ptpa1->a_address, ptpa2->b_address) &&
      IP_SAMEADDR (ptpa1->b_address, ptpa2->a_address) &&
      (ptpa1->a_port == ptpa2->b_port) && (ptpa1->b_port == ptpa2->a_port))
    return (S2C);

  /* different connection */
  return (0);
}

int
SameConn (tcp_pair_addrblock * ptpa1, tcp_pair_addrblock * ptpa2, int *pdir)
{
  /* if the hash values are different, they can't be the same */
  if (ptpa1->hash != ptpa2->hash)
    return (0);

  /* OK, they hash the same, are they REALLY the same function */
  *pdir = WhichDir (ptpa1, ptpa2);
  return (*pdir != 0);
}

int
ConnComplete (tcp_pair * ptp)
{
  return (ptp->c2s.closed && ptp->s2c.closed);
}


int
ConnReset (tcp_pair * ptp)
{
  return (ptp->c2s.reset_count + ptp->s2c.reset_count != 0);
}


extern Bool warn_MAX_;
static tcp_pair **
NewTTP_2 (struct ip *pip, struct tcphdr *ptcp)
{
  tcp_pair *ptp;
  int old_new_tcp_pairs = num_tcp_pairs;
  int steps = 0;

  /* look for the next eventually available free block */
  num_tcp_pairs++;
  num_tcp_pairs = num_tcp_pairs % GLOBALS.Max_TCP_Pairs;
  /* make a new one, if possible */
  while ((num_tcp_pairs != old_new_tcp_pairs) && (ttp[num_tcp_pairs] != NULL)
	 && (steps < GLOBALS.List_Search_Dept))
    {
      steps++;
      /* look for the next one */
//         fprintf (fp_stdout, "%d %d\n", num_tcp_pairs, old_new_tcp_pairs);
      num_tcp_pairs++;
      num_tcp_pairs = num_tcp_pairs % GLOBALS.Max_TCP_Pairs;
    }
  if (ttp[num_tcp_pairs] != NULL)
    {
      if (warn_MAX_)
	{
	  fprintf (fp_stderr, "\n" 
	    "ooopsss: number of simultaneous connection opened is greater then the maximum supported number!\n"
	    "you have to rebuild the source with a larger LIST_SEARCH_DEPT defined!\n"
	    "or possibly with a larger MAX_TCP_PAIRS defined!\n");
	}
      warn_MAX_ = FALSE;
      return (NULL);
    }

  /* create a new TCP pair record and remember where you put it */
  ptp = ttp[num_tcp_pairs] = tp_alloc ();

  /* grab the address from this packet */
  CopyAddr (&ptp->addr_pair,
	    pip, ntohs (ptcp->th_sport), ntohs (ptcp->th_dport));

  ptp->c2s.time.tv_sec = -1;
  ptp->s2c.time.tv_sec = -1;
  /* a.c */
  ptp->s2c.closed = FALSE;
  ptp->c2s.closed = FALSE;

  ptp->c2s.ptp = ptp;
  ptp->s2c.ptp = ptp;

  ptp->c2s.min_jitter = MAXFLOAT;
  ptp->s2c.min_jitter = MAXFLOAT;

  ptp->internal_src = internal_src;
  ptp->internal_dst = internal_dst;

  if (crypto_src)
   {
     if (ADDR_ISV6(&(ptp->addr_pair.a_address)))
       store_crypto_ipv6(&(ptp->addr_pair.a_address.un.ip6));
     else
       store_crypto_ip(&(ptp->addr_pair.a_address.un.ip4));
   }

  if (crypto_dst)
   {
     if (ADDR_ISV6(&(ptp->addr_pair.b_address)))
       store_crypto_ipv6(&(ptp->addr_pair.b_address.un.ip6));
     else
       store_crypto_ip(&(ptp->addr_pair.b_address.un.ip4));
   }

  ptp->crypto_src = crypto_src;
  ptp->crypto_dst = crypto_dst;
  
  /* Initialize the state */
  ptp->con_type = 0;
  ptp->state = UNKNOWN_TYPE;

  /* Assume all packets must be dumped */
  ptp->stop_dumping_tcp = FALSE;
/* DNS cache piece */
  /* Do reverse Lookup */
 if (dns_enabled)
  {
    if (PIP_ISV6(pip))
     { 
    struct DNS_data_IPv6* dns_data =  get_dns_entry_ipv6(&(PIP_V6(pip)->ip6_saddr), &(PIP_V6(pip)->ip6_daddr));
    if(dns_data!=NULL){
	 ptp->dns_name = dns_data->hostname;
	 ptp->dns_server.addr_vers = 6;
	 memcpy((&ptp->dns_server.un.ip6),&(dns_data->dns_server),sizeof(struct in6_addr));
	 ptp->request_time = dns_data->request_time;
	 ptp->response_time = dns_data->response_time;
	 ptp->crypto_dns = crypto_ipv6(ptp->dns_server.un.ip6);
     }
    if(debug >1)
     {
       fprintf (fp_stdout, "got DNS reverse %s %s ", ptp->dns_name, HostName (ptp->addr_pair.a_address));
       fprintf (fp_stdout, "from DNS server %s\n", HostName(ptp->dns_server));
     }
     }
    else
     {
    struct DNS_data* dns_data =  get_dns_entry(pip->ip_src.s_addr, pip->ip_dst.s_addr);
    if(dns_data!=NULL){
	 ptp->dns_name = dns_data->hostname;
	 ptp->dns_server.addr_vers = 4;
	 memcpy((&ptp->dns_server.un.ip4),&(dns_data->dns_server),sizeof(struct in_addr));
	 ptp->request_time = dns_data->request_time;
	 ptp->response_time = dns_data->response_time;
	 ptp->crypto_dns = crypto_ip(ptp->dns_server.un.ip4);
     }
    if(debug >1)
     {
       fprintf (fp_stdout, "got DNS reverse %s %s ", ptp->dns_name, HostName (ptp->addr_pair.a_address));
       fprintf (fp_stdout, "from DNS server %s\n", HostName(ptp->dns_server));
     }
     }
/* check if we are interested into dumping this flow packets accoring to the DNS name */
  ptp->stop_dumping_tcp = !check_DNSname(ptp->dns_name);
  }
 else
  ptp->dns_name = NULL;


  ptp->http_request_count  = 0;
  ptp->http_response_count = 0;

  ptp->http_hostname = NULL;

  ptp->ssl_client_subject = NULL;
  ptp->ssl_server_subject = NULL;

  ptp->ssl_client_tls_version = NULL;
  ptp->ssl_server_tls_version = NULL;

  ptp->ssl_client_npnalpn = TLS_EMPTY;
  ptp->ssl_server_npnalpn = TLS_EMPTY;

  ptp->ssl_client_data_seen = FALSE;
  ptp->ssl_server_data_seen = FALSE;

  ptp->ssl_client_data_byte = 0;
  ptp->ssl_server_data_byte = 0;
  
  ptp->ssl_client_PSK = FALSE;
  ptp->ssl_server_PSK = FALSE;
  ptp->ssl_client_early_data = FALSE;
  ptp->ssl_server_hello_retry = FALSE;

  ptp->ssl_client_hello_buffer = NULL;
  ptp->ssl_client_hello_offset = 0;
  ptp->ssl_client_hello_message_len = 0;
  
  // LOG_PERIODIC
  ptp->last_print_time = current_time;

  return (&ttp[num_tcp_pairs]);
}

static ptp_snap *
NewPTPH_2 (void)
{
  return (ptph_alloc ());
}


/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/

// ptp_snap *ptp_hashtable[HASH_TABLE_SIZE] = { NULL };
ptp_snap **ptp_hashtable;

static ptp_snap **
FindTTP (struct ip *pip, struct tcphdr *ptcp, int *pdir)
{

  ptp_snap **pptph_head = NULL;
  ptp_snap *ptph;
  ptp_snap *ptph_last;
  static tcp_pair **temp_ttp;

  tcp_pair_addrblock tp_in;
  int dir;
  hash hval;

  /* grab the address from this packet */
  CopyAddr (&tp_in, pip, ntohs (ptcp->th_sport), ntohs (ptcp->th_dport));

  /* grab the hash value (already computed by CopyAddr) */
  hval = tp_in.hash % GLOBALS.Hash_Table_Size;

  ptph_last = NULL;
  pptph_head = &ptp_hashtable[hval];


  for (ptph = *pptph_head; ptph; ptph = ptph->next)
    {
      ++search_count;

      if (SameConn (&tp_in, &ptph->addr_pair, &dir))
	{
	  /* OK, this looks good, suck it into memory */
	  tcp_pair *ptp = ptph->ptp;
	  tcb *thisdir;
	  tcb *otherdir;


	  /* figure out which direction this packet is going */
	  if (dir == C2S)
	    {
	      thisdir = &ptp->c2s;
	      otherdir = &ptp->s2c;
	    }
	  else
	    {
	      thisdir = &ptp->s2c;
	      otherdir = &ptp->c2s;
	    }

	  /* move to head of access list (unless already there) */
	  if (ptph != *pptph_head)
	    {
	      ptph_last->next = ptph->next;	/* unlink */
	      ptph->next = *pptph_head;	/* move to head */
	      *pptph_head = ptph;
	    }
	  *pdir = dir;
	  return (pptph_head);
	}
      ptph_last = ptph;
    }

  /* Didn't find it, make a new one, if possible */

  if (!(SYN_SET (ptcp) && !ACK_SET (ptcp)))
    {
      /* the new connection must begin with a SYN */
      if (debug > 1)
	{
	  fprintf (fp_stdout, 
        "** trash TCP packet: it does not belong to any known flows\n");
	}
      not_id_p++;

      return (NULL);
    }

  if (debug > 1)
    {
      fprintf (fp_stdout, "tracing a new TCP flow\n");
    }

  // we fire it at DOUBLE rate, but actually clean only those > TCP_IDLE_TIME
  if (elapsed (last_cleaned, current_time) > GLOBALS.GC_Fire_Time)
    {
      int i;
      for (i=0; i< elapsed (last_cleaned, current_time) / GLOBALS.GC_Fire_Time; i++ )
        trace_done_periodic ();
      last_cleaned = current_time;
    }


  add_histo (L4_flow_number, L4_FLOW_TCP);
  fcount++;
  f_TCP_count++;

  temp_ttp = NewTTP_2 (pip, ptcp);
  if (temp_ttp == NULL)		/* not enough memory to store the new flow */
    {
      /* the new connection must begin with a SYN */
      if (debug > 0)
	{
	  fprintf (fp_stdout, 
        "** out of memory when creating flows - considering a not_id_p\n");
	}
      not_id_p++;
      return (NULL);
    }
  tot_conn_TCP++;
  ptph = NewPTPH_2 ();
  ptph->ttp_ptr = temp_ttp;
  ptph->ptp = *(ptph->ttp_ptr);
  ptph->ptp->id_number = f_TCP_count;

  ptph->addr_pair = ptph->ptp->addr_pair;

  /* put at the head of the access list */
  ptph->next = *pptph_head;
  *pptph_head = ptph;

  *pdir = C2S;


  /* return the new ptph */
  return (pptph_head);
}

int
tcp_flow_stat (struct ip * pip, struct tcphdr * ptcp, void *plast, int *dir)
{
  struct tcp_options *ptcpo;
  tcp_pair *ptp_save;
  ptp_snap **ptph_ptr;
  ptp_snap *ptph_save;
  ptp_snap *ptph_tmp;
  int tcp_length;
  int tcp_data_length;
  u_long start;
  u_long end;
  tcb *thisdir;
  tcb *otherdir;
  tcp_pair tp_in;
  Bool is_retrans;
  Bool ecn_ce = FALSE;
  Bool ecn_echo = FALSE;
  Bool cwr = FALSE;
  int retrans_num_bytes;
  int retrans_actual_bytes;
  Bool out_order;		/* out of order */
  u_short th_sport;		/* source port */
  u_short th_dport;		/* destination port */
  tcp_seq th_seq;		/* sequence number */
  tcp_seq th_ack;		/* acknowledgement number */
  u_short th_win;		/* window */
  u_long eff_win;		/* window after scaling */
  short ip_len;			/* total length */
  enum t_ack ack_type = NORMAL;	/* how should we draw the ACK */
   /*TOPIX*/ double delta_t = 0;
  /*end TOPIX */

  /* make sure we have enough of the packet */
  if ((unsigned long) ptcp + sizeof (struct tcphdr) - 1 >
      (unsigned long) plast)
    {
      if (warn_printtrunc)
	fprintf (fp_stderr,
		 "TCP packet %lu truncated too short (%ld) to trace, ignored\n",
		 pnum,
		 (unsigned long) ptcp + sizeof (struct tcphdr) -
		 (unsigned long) plast);
      ++ctrunc;
      return (FLOW_STAT_SHORT);
    }


  /* convert interesting fields to local byte order */
  th_seq = ntohl (ptcp->th_seq);
  th_ack = ntohl (ptcp->th_ack);
  th_sport = ntohs (ptcp->th_sport);
  th_dport = ntohs (ptcp->th_dport);
  th_win = ntohs (ptcp->th_win);
  ip_len = gethdrlength (pip, plast) + getpayloadlength (pip, plast);


  /* make sure this is one of the connections we want */
  ptph_ptr = FindTTP (pip, ptcp, dir);

  /* if the connection is not to be analyzed return a NULL */
  if (ptph_ptr == NULL)
    {
      return (FLOW_STAT_NULL);
    }

  ptph_save = (*ptph_ptr);
  ptp_save = ptph_save->ptp;


  if (ptp_save == NULL)
    {
      return (FLOW_STAT_NULL);
    }

  if (internal_src && !internal_dst)
    {
      ++tcp_trace_count_outgoing;
    }
  else if (!internal_src && internal_dst)
    {
      ++tcp_trace_count_incoming;
    }
  else if (internal_src && internal_dst)
    {
      ++tcp_trace_count_local;
    }


  /*MT: log periodic - Do this before updating counters*/
    if ( elapsed(ptp_save->last_print_time, current_time) > GLOBALS.Log_Periodic_Interval) {

      print_periodic_log(ptp_save);

   }


  /* do time stats */
  if (ZERO_TIME (&ptp_save->first_time))
    {
      ptp_save->first_time = current_time;
    }
  ptp_save->last_time = current_time;


  /* bug fix:  it's legal to have the same end points reused.  The */
  /* program uses a heuristic of looking at the elapsed time from */
  /* the last packet on the previous instance and the number of FINs */
  /* in the last instance.  If we don't increment the fin_count */
  /* before bailing out in "ignore_pair" below, this heuristic breaks */

  /* figure out which direction this packet is going */
  if (*dir == C2S)
    {
      thisdir = &ptp_save->c2s;
      otherdir = &ptp_save->s2c;
    }
  else
    {
      thisdir = &ptp_save->s2c;
      otherdir = &ptp_save->c2s;
    }


  /* calculate data length */
  tcp_length = getpayloadlength (pip, plast);
  tcp_data_length = tcp_length - (4 * ptcp->th_off);

  /* meta connection stats */
  if (SYN_SET (ptcp))
    ++thisdir->syn_count;
  if (RESET_SET (ptcp))
    ++thisdir->reset_count;
  if (FIN_SET (ptcp))
    {
      ++thisdir->fin_count;
      thisdir->fin_seqno = th_seq + tcp_data_length;
    }
  /* sanity check - stop tracking this flow if we got a SYN */
  /* from the client, no SYN+ACK from the server */
  /* and this is a data packet from the client */
  /* indeed, if no SYN+ACK has been seen, then this must be an */
  /* half flow... force a false RST message to close this flow */

  if ((*dir == C2S) && (!SYN_SET (ptcp)) && (otherdir->syn_count == 0) && tcp_data_length != 0 )
    {
      //fprintf (fp_stdout, "  Closing a half duplex flow\n");
      tot_conn_TCP--;
      make_conn_stats (ptp_save,
		       (ptp_save->s2c.syn_count > 0
			&& ptp_save->c2s.syn_count > 0));

      /* free up memory for this flow */

      free_tp (ptp_save);

      /* free up the first element of the list pointer by the hash */
      ptph_tmp = ptph_save;
      *(ptph_save->ttp_ptr) = NULL;
      *ptph_ptr = ptph_save->next;
      ptph_release (ptph_tmp);

      return (FLOW_STAT_OK);
    }

  if ((ACK_SET (ptcp)) &&
      (otherdir->fin_count >= 1) && (th_ack >= (otherdir->fin_seqno + 1)))
    {
      // This is the ACK to the FIN
      otherdir->closed = TRUE;
    }

  if (ACK_SET (ptcp) && otherdir->cwnd_flag)
    {
      add_histo (tcp_cwnd, (otherdir->seq - thisdir->ack));

      /* we already counted this flight-size, then do not 
       * consider it anymore until some new data will be received on the
       * backward direction.
       */
      otherdir->cwnd_flag = 0;
    }

  /* compute the "effective window", which is the advertised window */
  /* with scaling */
  if (ACK_SET (ptcp) || SYN_SET (ptcp))
    {
      eff_win = (u_long) th_win;

      /* N.B., the window_scale stored for the connection DURING 3way */
      /* handshaking is the REQUESTED scale.  It's only valid if both */
      /* sides request scaling.  AFTER we've seen both SYNs, that field */
      /* is reset (above) to contain zero.  Note that if we */
      /* DIDN'T see the SYNs, the windows will be off. */
      if (thisdir->f1323_ws && otherdir->f1323_ws)
	eff_win <<= thisdir->window_scale;
    }
  else
    {
      eff_win = 0;
    }


  /* idle-time stats */
  if (!ZERO_TIME (&thisdir->last_time))
    {
      u_llong itime = elapsed (thisdir->last_time, current_time);
      delta_t = (double) itime;
    }
  thisdir->last_time = current_time;

  /* congestion window 
   * This is a new data segment which enable the cwnd evaluation
   */
  if ((tcp_data_length != 0) || SYN_SET (ptcp) || FIN_SET (ptcp)
      || RESET_SET (ptcp))
    {
      thisdir->cwnd_flag = 1;
    }

  /* calc. data range */
  start = th_seq;
  end = start + tcp_data_length;

  /* record sequence limits */
  if (SYN_SET (ptcp))
    {
      /* error checking - better not change! */
      if ((thisdir->syn_count > 1) && (thisdir->syn != start))
	{
	  /* it changed, that shouldn't happen! */
	  if (warn_printbad_syn_fin_seq)
	    fprintf (fp_stderr,
		     "rexmitted SYN had diff. seqnum! (was %lu, now %lu, etime: %d sec)\n",
		     thisdir->syn, start,
		     (int) (elapsed (ptp_save->first_time, current_time) / 1000000));
	  thisdir->bad_behavior = TRUE;
	}
      thisdir->syn = start;
      otherdir->ack = start;
      /* bug fix for Rob Austein <sra@epilogue.com> */
    }
  if (FIN_SET (ptcp))
    {
      /* bug fix, if there's data here too, we need to bump up the FIN */
      /* (psc data file shows example) */
      u_long fin = start + tcp_data_length;
      /* error checking - better not change! */
      if ((thisdir->fin_count > 1) && (thisdir->fin != fin))
	{
	  /* it changed, that shouldn't happen! */
	  if (warn_printbad_syn_fin_seq)
	    fprintf (fp_stderr,
		     "rexmitted FIN had diff. seqnum! (was %lu, now %lu, etime: %d sec)\n",
		     thisdir->fin, fin,
		     (int) (elapsed (ptp_save->first_time, current_time) /
			    1000000));
	  thisdir->bad_behavior = TRUE;
	}
      thisdir->fin = fin;
    }

  /* "ONLY" bug fix - Wed Feb 24, 1999 */
  /* the tcp-splicing heuristic needs "windowend", which was only being */
  /* calculated BELOW the "only" point below.  Move that part of the */
  /* calculation up here! */

  if (ACK_SET (ptcp))
    {
      thisdir->windowend = th_ack + eff_win;
    }
  /* end bugfix */

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip, th_sport, th_dport);


  /* check the options */
  ptcpo = ParseOptions (ptcp, plast);
  if (ptcpo->mss != -1)
    thisdir->mss = ptcpo->mss;
  if (ptcpo->ws != -1)
    {
      thisdir->window_scale = ptcpo->ws;
      thisdir->f1323_ws = TRUE;
    }
  if (ptcpo->tsval != -1)
    {
      thisdir->f1323_ts = TRUE;
    }
  /* NOW, unless BOTH sides asked for window scaling in their SYN     */
  /* segments, we aren't using window scaling */
  if (!SYN_SET (ptcp) && ((!thisdir->f1323_ws) || (!otherdir->f1323_ws)))
    {
      thisdir->window_scale = otherdir->window_scale = 0;
    }

  /* check sacks */
  if (ptcpo->sack_req)
    {
      thisdir->fsack_req = 1;
    }
  if (ptcpo->sack_count > 0)
    {
      ++thisdir->sacks_sent;
    }

  /* check mptcp */
  if (ptcpo->mptcp_req)
    {
      thisdir->mptcp_req = 1;
    }


  if (*dir == C2S)
    ptp_save->c2s.ip_bytes += ip_len;
  else
    ptp_save->s2c.ip_bytes += ip_len;

  /* do data stats */
  if (tcp_data_length > 0)
    {
      thisdir->data_pkts += 1;
      if (PUSH_SET (ptcp))
	thisdir->data_pkts_push += 1;
      thisdir->data_bytes += tcp_data_length;
      if (tcp_data_length > thisdir->max_seg_size)
	thisdir->max_seg_size = tcp_data_length;
      if ((thisdir->min_seg_size == 0) ||
	  (tcp_data_length < thisdir->min_seg_size))
	thisdir->min_seg_size = tcp_data_length;
      /* record first and last times for data (Mallman) */
      if (ZERO_TIME (&thisdir->first_data_time))
	thisdir->first_data_time = current_time;
      thisdir->last_data_time = current_time;
#ifdef PACKET_STATS
      thisdir->data_pkts_sum2 += tcp_data_length*tcp_data_length; 
      
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
         thisdir->seg_size[thisdir->seg_count] = tcp_data_length;
	 if (thisdir->seg_count>0)
	  {
	    thisdir->seg_intertime[thisdir->seg_count-1] = current_intertime;
	  }
       }

	 thisdir->seg_count++;
      }
#endif


    }

  /*TTL stats */
  if (PIP_ISV4(pip))
  {
    if ((thisdir->ttl_min == 0) || (thisdir->ttl_min > (int) pip->ip_ttl))
      thisdir->ttl_min = (int) pip->ip_ttl;
    if (thisdir->ttl_max < (int) pip->ip_ttl)
      thisdir->ttl_max = (int) pip->ip_ttl;

     /*TOPIX*/ thisdir->ttl_tot += (u_llong) pip->ip_ttl;
     /*TOPIX*/
    }
  else
  {
    if ((thisdir->ttl_min == 0) || (thisdir->ttl_min > (int) PIP_V6(pip)->ip6_hlimit))
      thisdir->ttl_min = (int) PIP_V6(pip)->ip6_hlimit;
    if (thisdir->ttl_max < (int) PIP_V6(pip)->ip6_hlimit)
      thisdir->ttl_max = (int) PIP_V6(pip)->ip6_hlimit;

     /*TOPIX*/ thisdir->ttl_tot += (u_llong) PIP_V6(pip)->ip6_hlimit;
     /*TOPIX*/
  }
    /* total packets stats */
    ++ptp_save->packets;
  ++thisdir->packets;

  if(end > thisdir->max_seq)
    thisdir->max_seq = end;


  /* Kevin Lahey's ECN code */
  /* only works for IPv4 */
  if (PIP_ISV4 (pip))
    {
      ecn_ce = IP_ECT (pip) && IP_CE (pip);
    }
  cwr = CWR_SET (ptcp);
  ecn_echo = ECN_ECHO_SET (ptcp);

  /* do rexmit stats */
  is_retrans = FALSE;
  out_order = FALSE;
  retrans_num_bytes = 0;
  retrans_actual_bytes = 0;
  if (SYN_SET (ptcp) || FIN_SET (ptcp) || tcp_data_length > 0)
    {
      int len = tcp_data_length;

      if (SYN_SET (ptcp))
	++len;
      if (FIN_SET (ptcp))
	++len;

      retrans_num_bytes =
	rexmit (thisdir, start, len, &out_order, pip->ip_id);
      retrans_actual_bytes = retrans_num_bytes;	
	
      /* count anything NOT retransmitted as "unique" */
      /* exclude SYN and FIN */
      if (SYN_SET (ptcp))
	{
	  /* don't count the SYN as data */
	  --len;
	  /* if the SYN was rexmitted, then don't count it */
	  if (thisdir->syn_count > 1 && retrans_actual_bytes > 0 )
            --retrans_actual_bytes;
	}
      if (FIN_SET (ptcp))
	{
	  /* don't count the FIN as data */
	  --len;
	  /* if the FIN was rexmitted, then don't count it */
	  if (thisdir->fin_count > 1  && retrans_actual_bytes > 0)
            --retrans_actual_bytes;
	}
      if (retrans_actual_bytes < len)
	thisdir->unique_bytes += (len - retrans_actual_bytes);

    }
  if (out_order)
    thisdir->out_order_pkts++;

   /*TOPIX*/
    /* delta_t evaluation if packets are data packets */
    if (tcp_data_length > 0)
    {
      double jitter;
      /* delta_t in milliseconds */
      delta_t = delta_t / 1000.0;
      thisdir->sum_delta_t += delta_t;
      thisdir->n_delta_t++;
      jitter = delta_t - thisdir->sum_delta_t / thisdir->n_delta_t;
      if (jitter < 0)
	jitter = -jitter;
      thisdir->sum_jitter += jitter;
      if (thisdir->max_jitter < jitter)
	thisdir->max_jitter = jitter;
      if (thisdir->min_jitter > jitter)
	thisdir->min_jitter = jitter;

    }
  /*end TOPIX */


  /* do rtt stats */
  if (ACK_SET (ptcp))
    {
      ack_type = ack_in (otherdir, th_ack, tcp_data_length);
    }

  /* stats for rexmitted data */
  if (retrans_num_bytes > 0)
    {
      is_retrans = TRUE;
      thisdir->rexmit_pkts += 1;
      thisdir->rexmit_bytes += retrans_actual_bytes;
    }
  else
    {
      thisdir->seq = end;
    }

  /* check for RESET */
  if (RESET_SET (ptcp))
    {

      if (ACK_SET (ptcp))
	++thisdir->ack_pkts;

      /* make upper layer protocol analysis and update the classified bitrate */
      /* Probably harmless because the RESET should not have payload, but 
         this is the only way to call the dump plugin */

      proto_analyzer (pip, ptcp, PROTOCOL_TCP, thisdir, *dir, plast);

      if (thisdir != NULL && thisdir->ptp != NULL)
       {
	    make_tcpL7_rate_stats(thisdir->ptp, ip_len);
       }
      /* */
      
      if (ConnReset (ptp_save))
	{
	  //fprintf (fp_stdout, "  (new reset)\n");
	  tot_conn_TCP--;
	  make_conn_stats (ptp_save,
			   (ptp_save->s2c.syn_count > 0
			    && ptp_save->c2s.syn_count > 0));

	  /* free up memory for this flow */

	  free_tp (ptp_save);

	  /* free up the first element of the list pointer by the hash */
	  ptph_tmp = ptph_save;
	  *(ptph_save->ttp_ptr) = NULL;
	  *ptph_ptr = ptph_save->next;
	  ptph_release (ptph_tmp);
	}

      return (FLOW_STAT_OK);
    }


  /* do window stats (include first SYN too!) */
  if (ACK_SET (ptcp) || SYN_SET (ptcp))
    {
      thisdir->win_curr = eff_win;
      if (eff_win > thisdir->win_max)
	thisdir->win_max = eff_win;
      if ((eff_win > 0) &&
	  ((thisdir->win_min == 0) || (eff_win < thisdir->win_min)))
	thisdir->win_min = eff_win;
      thisdir->win_tot += eff_win;
    }

  if (ACK_SET (ptcp))
    {
      seqnum ack = th_ack;
      u_long winend;

      winend = ack + eff_win;

      if (eff_win == 0)
	++thisdir->win_zero_ct;

      ++thisdir->ack_pkts;
      if ((tcp_data_length == 0) &&
	  !SYN_SET (ptcp) && !FIN_SET (ptcp) && !RESET_SET (ptcp))
	{
	  ++thisdir->pureack_pkts;
	}

      thisdir->time = current_time;
      thisdir->ack = ack;

    }

  /* do stats for initial window (first slow start) */
  /* (if there's data in this and we've NEVER seen */
  /*  an ACK coming back from the other side) */
  /* this is for Mark Allman for slow start testing -- Mon Mar 10, 1997 */
  if (!otherdir->data_acked && ACK_SET (ptcp)
      && ((otherdir->syn + 1) != th_ack))
    {
      otherdir->data_acked = TRUE;
    }
  if ((tcp_data_length > 0) && (!thisdir->data_acked))
    {
      if (!is_retrans)
	{
	  /* don't count it if it was retransmitted */
	  thisdir->initialwin_bytes += tcp_data_length;
	  thisdir->initialwin_segs += 1;
	}
    }

  if (SYN_SET (ptcp) && !ACK_SET (ptcp))
    {
      thisdir->highest_seqno = thisdir->max_seq;
    }

  if (ACK_SET(ptcp) && !SYN_SET(ptcp))
    {
       if (ZERO_TIME(&(thisdir->ack_start_time)))
        {
	  thisdir->ack_start_time = current_time;
	}    
    }

  /* check if this segment is carrying the first data */
  if (thisdir->payload_start_time.tv_sec == 0 &&
      thisdir->payload_start_time.tv_usec == 0 && tcp_data_length != 0)
    {
      thisdir->payload_start_time = current_time;
    }

  /* check if this segment is carrying new or retransmitted data */
  if (tcp_data_length != 0)
    {
      thisdir->payload_end_time = current_time;
    }

  /* do stats for congestion window (estimated) */
  /* estimate the congestion window as the number of outstanding */
  /* un-acked bytes */
  if (!SYN_SET (ptcp) && !out_order && !is_retrans)
    {
      u_int32_t cwin = end - otherdir->ack;

      if ((int32_t) cwin > 0 && cwin > thisdir->cwin_max) {
	thisdir->cwin_max = cwin;
        }
      if ((int32_t) cwin > 0 && ((thisdir->cwin_min == 0) || (cwin < thisdir->cwin_min)))
	thisdir->cwin_min = cwin;
       
      if ((int32_t) cwin > 0 && cwin > thisdir->cwin_max_periodic ) {
	    thisdir->cwin_max_periodic = cwin;
        }
      if ((int32_t) cwin > 0 && ((thisdir->cwin_min_periodic == 0) || (cwin < thisdir->cwin_min_periodic))){
	    thisdir->cwin_min_periodic = cwin;
        }

    }

  /* Count TCP messages and track message sizes.
     We split messages on PSH segments 
  */
  if (ACK_SET(ptcp))
   {
     if ( (PUSH_SET(ptcp)||FIN_SET(ptcp)) && 
           thisdir->msg_last_seq < thisdir->seq) 
      {
        u_int curr_msg_size = thisdir->msg_last_seq==0 ? 
	                           thisdir->seq - thisdir->syn - 1 :
	                           thisdir->seq - thisdir->msg_last_seq;
	if (thisdir->msg_count<MAX_COUNT_MESSAGES)
          thisdir->msg_size[thisdir->msg_count]= curr_msg_size;
        if (curr_msg_size>0) thisdir->msg_count++;
        thisdir->msg_last_seq = thisdir->seq;
     }

   }

  /* make upper layer protocol analysis and update the classified bitrate */

  proto_analyzer (pip, ptcp, PROTOCOL_TCP, thisdir, *dir, plast);

  if (thisdir != NULL && thisdir->ptp != NULL)
   {
     make_tcpL7_rate_stats(thisdir->ptp, ip_len);
   }
  

  /* Check if the connection is completed */

  if (ConnComplete (ptp_save))
    {
      //fprintf (fp_stdout, "  (new complete)\n");
      tot_conn_TCP--;
      make_conn_stats (ptp_save, TRUE);

      /* free up memory for this flow */

      free_tp (ptp_save);

      /* free up the first element of the list pointedby the hash */
      ptph_tmp = ptph_save;
      *(ptph_save->ttp_ptr) = NULL;

      /* ptph_ptr is the head, pointed by the hash */
      /* recall the this element is the first, as it has been moved by the
         FindTTP() */
      *ptph_ptr = ptph_save->next;
      ptph_release (ptph_tmp);
    }
  return (FLOW_STAT_OK);
}


void
trace_done (void)
{
  tcp_pair *ptp;
  int ix;


  for (ix = 0; ix < GLOBALS.Max_TCP_Pairs; ++ix)
    {
      ptp = ttp[ix];

      if (ptp == NULL)
	continue;

      if (( (
             (
	      (ptp->c2s.syn_count>0 && ptp->s2c.syn_count==0)
              ||
	      (ptp->c2s.syn_count==0 && ptp->s2c.syn_count>0)
	     ) 
	     &&
	     (
	      ptp->packets == (ptp->c2s.syn_count+ptp->s2c.syn_count)
	     )
	    )
            && 
	    (elapsed (ptp->last_time, current_time) > GLOBALS.TCP_Singleton_Time)
	  )
	  ||
          (elapsed (ptp->last_time, current_time) > GLOBALS.TCP_Idle_Time))
	{
	  
	  make_conn_stats (ptp, (ptp->s2c.syn_count > 0)
			   && (ptp->c2s.syn_count > 0));

	  tot_conn_TCP--;

	  ttp[ix] = NULL;

	}

    }


  for (ix = 0; ix < GLOBALS.Max_TCP_Pairs; ++ix)
    {
      ptp = ttp[ix];
      if (ptp == NULL)		// already analyzed
	continue;

      // do not consider this flow for the stats
      make_conn_stats (ptp, FALSE);
      tot_conn_TCP--;
    }
}

long int counter = 0;

void
trace_done_periodic ()
{
  tcp_pair *ptp;
  udp_pair *pup;
  int ix, dir, j;
  //unsigned int cleaned = 0;
  unsigned long init_tot_conn = tot_conn_TCP;
  extern ptp_snap **ptp_hashtable;

  hash hval;
  ptp_snap *ptph_tmp, *ptph, *ptph_prev;
  ptp_snap **pptph_head = NULL;

 /* complete the "idle time" calculations using NOW */
  if (printticks && debug > 1)
    fprintf (fp_stdout, "\nStart cleaning TCP flows\n");
  for (ix = tcp_index; ix < GLOBALS.Max_TCP_Pairs; ix += GLOBALS.GC_Split_Ratio )
    {
      ptp = ttp[ix];

      if (ptp == NULL)
	continue;

      /* If no packets have been received in the last IDLE_TIME period,
         close the flow */
      if (( (
             (
	      (ptp->c2s.syn_count>0 && ptp->s2c.syn_count==0)
              ||
	      (ptp->c2s.syn_count==0 && ptp->s2c.syn_count>0)
	     ) 
	     &&
	     (
	      ptp->packets == (ptp->c2s.syn_count+ptp->s2c.syn_count)
	     )
	    )
            && 
	    (elapsed (ptp->last_time, current_time) > GLOBALS.TCP_Singleton_Time)
	  )
	  ||
          (elapsed (ptp->last_time, current_time) > GLOBALS.TCP_Idle_Time))
	{
	  /* must be cleaned */
	  //tcp_cleaned++;

	  make_conn_stats (ptp, (ptp->s2c.syn_count > 0)
			   && (ptp->c2s.syn_count > 0));

	  tot_conn_TCP--;

	  /* free up hash element->.. */
	  hval = ptp->addr_pair.hash % GLOBALS.Hash_Table_Size;

	  pptph_head = &ptp_hashtable[hval];
	  j = 0;
	  ptph_prev = *pptph_head;
	  for (ptph = *pptph_head; ptph; ptph = ptph->next)
	    {
	      j++;
	      if (SameConn (&ptp->addr_pair, &ptph->addr_pair, &dir))
		{
		  ptph_tmp = ptph;
		  if (j == 1)
		    {
		      /* it is the top of the list */
		      ptp_hashtable[hval] = ptph->next;
		    }
		  else
		    {
		      /* it is in the middle of the list */
		      ptph_prev->next = ptph->next;
		    }
		  ptph_release (ptph_tmp);
		  break;
		}
	      ptph_prev = ptph;
	    }

	  /* ... and free up the TP. */
	  free_tp (ptp);
	  ttp[ix] = NULL;
	}

    }

  /* Increasing starting index for the next function call */
  tcp_index = (tcp_index + 1) % GLOBALS.GC_Split_Ratio ;

  if (printticks && debug > 1)
    fprintf (fp_stdout,
	     "\rCleaned %d/(%ld) TCP flows\n", tcp_cleaned, init_tot_conn);

  if (do_udp == FALSE)
    return;
 /************ Start cleaning UDP flows *******************/


  if (printticks && debug > 1)
    fprintf (fp_stdout, "Start cleaning UDP flows\n");

  //cleaned = 0;
  init_tot_conn = tot_conn_UDP;
  for (ix = udp_index; ix < GLOBALS.Max_UDP_Pairs; ix += GLOBALS.GC_Split_Ratio )
    {
      pup = utp[ix];

      if (pup == NULL)
	continue;

      /* If no packets have been received in the last UDP_IDLE_TIME period,
         close the flow */
      if (( (pup->packets == 1) && 
	    (elapsed (pup->last_time, current_time) > GLOBALS.UDP_Singleton_Time)
	  )
	  ||
          (elapsed (pup->last_time, current_time) > GLOBALS.UDP_Idle_Time))
	{
	   close_udp_flow (pup, ix, dir);
           udp_cleaned++;
	}

    }

  /* Increasing starting index for the next function call */
  udp_index = (udp_index + 1) % GLOBALS.GC_Split_Ratio ;

	//if (counter++%500 == 0)printf("Cleaned %d flows\n", cleaned);

  if (printticks && debug > 1)
    fprintf (fp_stdout,
	     "\rCleaned %d/(%ld) UDP flows\n", udp_cleaned, init_tot_conn);
}

void
trace_init (void)
{
  static Bool initted = FALSE;
  extern ptp_snap **ptp_hashtable;

  if (initted)
    return;

  initted = TRUE;

  /* initialize the hash table */

  ptp_hashtable = (ptp_snap **) MallocZ (GLOBALS.Hash_Table_Size * sizeof (ptp_snap *));

  /* create an array to hold any pairs that we might create */
  ttp = (tcp_pair **) MallocZ (GLOBALS.Max_TCP_Pairs * sizeof (tcp_pair *));
}


/* get a long (4 byte) option (to avoid address alignment problems) */
static u_long
get_long_opt (void *ptr)
{
  u_long l;
  memcpy (&l, ptr, sizeof (u_long));
  return (l);
}


/* get a short (2 byte) option (to avoid address alignment problems) */
static u_short
get_short_opt (void *ptr)
{
  u_short s;
  memcpy (&s, ptr, sizeof (u_short));
  return (s);
}


struct tcp_options *
ParseOptions (struct tcphdr *ptcp, void *plast)
{
  static struct tcp_options tcpo;
  struct sack_block *psack;
  u_char *pdata;
  u_char *popt;
  u_char *plen;

  popt = (u_char *) ptcp + sizeof (struct tcphdr);
  pdata = (u_char *) ptcp + ptcp->th_off * 4;
  /* init the options structure */
  memset (&tcpo, 0, sizeof (tcpo));
  tcpo.mss = tcpo.ws = tcpo.tsval = tcpo.tsecr = -1;
  tcpo.sack_req = 0;
  tcpo.sack_count = -1;
  tcpo.echo_req = tcpo.echo_repl = -1;
  tcpo.cc = tcpo.ccnew = tcpo.ccecho = -1;

  /* a quick sanity check, the unused (MBZ) bits must BZ! */
  if (warn_printbadmbz)
    {
      if (ptcp->th_x2 != 0)
	{
	  fprintf (fp_stderr,
		   "TCP packet %lu: 4 reserved bits are not zero (0x%01x)\n",
		   pnum, ptcp->th_x2);
	}
      if ((ptcp->th_flags & 0xc0) != 0)
	{
	  fprintf (fp_stderr,
		   "TCP packet %lu: upper flag bits are not zero (0x%02x)\n",
		   pnum, ptcp->th_flags);
	}
    }
  else
    {
      static int warned = 0;
      if (!warned && ((ptcp->th_x2 != 0) || ((ptcp->th_flags & 0xc0) != 0)))
	{
	  warned = 1;
	  fprintf (fp_stderr, "\
TCP packet %lu: reserved bits are not all zero.  \n\
\tFurther warnings disabled, use '-w' for more info\n", pnum);
	}
    }

  /* looks good, now check each option in turn */
  while (popt < pdata)
    {
      plen = popt + 1;
      /* check for truncation error */
      if ((unsigned long) popt > (unsigned long) plast)
	{
	  if (warn_printtrunc)
	    fprintf (fp_stderr, "\
ParseOptions: packet %lu too short (%lu) to parse remaining options\n", pnum, (unsigned long) popt - (unsigned long) plast + 1);
	  ++ctrunc;
	  break;
	}

#define CHECK_O_LEN(opt) \
	if (*plen == 0) { \
	    if (warn_printtrunc) fprintf (fp_stderr, "\
ParseOptions: packet %lu %s option has length 0, skipping other options\n", \
                                           pnum,opt); \
	    popt = pdata; break;} \
	if ((unsigned long)popt + *plen - 1 > (unsigned long)(plast)) { \
	    if (warn_printtrunc) \
		fprintf (fp_stderr, "\
ParseOptions: packet %lu %s option truncated, skipping other options\n", \
              pnum,opt); \
	    ++ctrunc; \
	    popt = pdata; break;} \


      switch (*popt)
	{
	case TCPOPT_EOL:
	  ++popt;
	  break;
	case TCPOPT_NOP:
	  ++popt;
	  break;
	case TCPOPT_MAXSEG:
	  CHECK_O_LEN ("TCPOPT_MAXSEG");
	  tcpo.mss = ntohs (get_short_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_WS:
	  CHECK_O_LEN ("TCPOPT_WS");
	  tcpo.ws = *((u_char *) (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_TS:
	  CHECK_O_LEN ("TCPOPT_TS");
	  tcpo.tsval = ntohl (get_long_opt (popt + 2));
	  tcpo.tsecr = ntohl (get_long_opt (popt + 6));
	  popt += *plen;
	  break;
	case TCPOPT_ECHO:
	  CHECK_O_LEN ("TCPOPT_ECHO");
	  tcpo.echo_req = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_ECHOREPLY:
	  CHECK_O_LEN ("TCPOPT_ECHOREPLY");
	  tcpo.echo_repl = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_CC:
	  CHECK_O_LEN ("TCPOPT_CC");
	  tcpo.cc = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_CCNEW:
	  CHECK_O_LEN ("TCPOPT_CCNEW");
	  tcpo.ccnew = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_CCECHO:
	  CHECK_O_LEN ("TCPOPT_CCECHO");
	  tcpo.ccecho = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_SACK_PERM:
	  CHECK_O_LEN ("TCPOPT_SACK_PERM");
	  tcpo.sack_req = 1;
	  popt += *plen;
	  break;
	case TCPOPT_SACK:
	  /* see which bytes are acked */
	  CHECK_O_LEN ("TCPOPT_SACK");
	  tcpo.sack_count = 0;
	  psack = (sack_block *) (popt + 2);	/* past the kind and length */
	  popt += *plen;
	  while ((unsigned long) psack < (unsigned long) popt)
	    {
	      struct sack_block *psack_local =
		&tcpo.sacks[(unsigned) tcpo.sack_count];
	      /* warning, possible alignment problem here, so we'll
	         use memcpy() and hope for the best */
	      /* better use -fno-builtin to avoid gcc alignment error
	         in GCC 2.7.2 */
	      memcpy (psack_local, psack, sizeof (sack_block));

	      /* convert to local byte order (Jamshid Mahdavi) */
	      psack_local->sack_left = ntohl (psack_local->sack_left);
	      psack_local->sack_right = ntohl (psack_local->sack_right);

	      ++psack;
	      if ((unsigned long) psack > ((unsigned long) plast + 1))
		{
		  /* this SACK block isn't all here */
		  if (warn_printtrunc)
		    fprintf (fp_stderr, "packet %lu: SACK block truncated\n",
			     pnum);
		  ++ctrunc;
		  break;
		}
	      ++tcpo.sack_count;
	      if (tcpo.sack_count > MAX_SACKS)
		{
		  /* this isn't supposed to be able to happen */
		  fprintf (fp_stderr,
			   "Warning, internal error, too many sacks!!\n");
		  tcpo.sack_count = MAX_SACKS;
		}
	    }
	  break;
	case TCPOPT_MPTCP:
	  CHECK_O_LEN ("TCPOPT_MPTCP");
	  tcpo.mptcp_req = 1;
	  popt += *plen;
	  break;

	default:
	  if (debug)
	    fprintf (fp_stderr,
		     "Warning, ignoring unknown TCP option 0x%x\n", *popt);
	  CHECK_O_LEN ("TCPOPT_UNKNOWN");

	  /* record it anyway... */
	  if (tcpo.unknown_count < MAX_UNKNOWN)
	    {
	      int ix = tcpo.unknown_count;	/* make lint happy */
	      tcpo.unknowns[ix].unkn_opt = *popt;
	      tcpo.unknowns[ix].unkn_len = *plen;
	    }
	  ++tcpo.unknown_count;

	  popt += *plen;
	  break;
	}
    }

  return (&tcpo);
}


/*
** Functions to print selected groups of TCP measurements
*/

void print_tcp_stats_core(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  double etime;

  /* connection time and throughput */
  /* from microseconds to ms */
  etime = elapsed (ptp_save->first_time, ptp_save->last_time);
  etime = etime / 1000;

  /* Core Tstat TCP measurements */
  if (ptp_save->crypto_src==FALSE)
   {
     wfprintf (fp, "%s", HostName (ptp_save->addr_pair.a_address));
   }   
  else
   {
     wfprintf (fp, "%s", HostNameEncrypted (ptp_save->addr_pair.a_address));
   }
  wfprintf (fp, 
    	   " %s %lu %u %lu %lu %lu %lu %lu %u %u %u %d %d",
    	   ServiceName (ptp_save->addr_pair.a_port),
    	   pab->packets,
    	   pab->reset_count,
    	   pab->ack_pkts,
    	   pab->pureack_pkts,
    	   pab->unique_bytes,
    	   pab->data_pkts,
    	   pab->data_bytes,
    	   pab->rexmit_pkts,
    	   pab->rexmit_bytes,
    	   pab->out_order_pkts,
    	   pab->syn_count,
    	   pab->fin_count);
  if (ptp_save->crypto_dst==FALSE)
   {
     wfprintf (fp, " %s", HostName (ptp_save->addr_pair.b_address));
   }   
  else
   {
     wfprintf (fp, " %s", HostNameEncrypted (ptp_save->addr_pair.b_address));
   }
  wfprintf (fp,
    	   " %s %lu %u %lu %lu %lu %lu %lu %u %u %u %d %d",
    	   ServiceName (ptp_save->addr_pair.b_port),
    	   pba->packets,
    	   pba->reset_count,
    	   pba->ack_pkts,
    	   pba->pureack_pkts,
    	   pba->unique_bytes,
    	   pba->data_pkts,
    	   pba->data_bytes,
    	   pba->rexmit_pkts,
    	   pba->rexmit_bytes,
    	   pba->out_order_pkts,
    	   pba->syn_count,
    	   pba->fin_count);

  /* first pkt time */
  wfprintf (fp, " %f",time2double(ptp_save->first_time) / 1000.0);
  /* last pkt time */
  wfprintf (fp, " %f",time2double(ptp_save->last_time) / 1000.0);

  /* elapsed time */
  wfprintf (fp, " %f", etime);

  /* first DATA pkt time */
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pab->payload_start_time) / 1000.0);
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pba->payload_start_time) / 1000.0);

  /* last DATA pkt time */
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pab->payload_end_time) / 1000.0);
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pba->payload_end_time) / 1000.0);
  /* first ACK pkt time */
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pab->ack_start_time) / 1000.0);
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pba->ack_start_time) / 1000.0);

  /* printing boolean flag if source is considered internal or not */
  wfprintf (fp, " %d", ptp_save->internal_src);
  /* printing boolean flag if destination is considered internal or not */
  wfprintf (fp, " %d", ptp_save->internal_dst);

  /* printing boolean flag if source is anonymized or not */
  wfprintf (fp, " %d", ptp_save->crypto_src);
  /* printing boolean flag if destination is anonymized or not */
  wfprintf (fp, " %d", ptp_save->crypto_dst);

  /* TOPIX: added 97th column: connection type */
  wfprintf (fp, " %d", ptp_save->con_type);

/* End of the Core TCP set */
}

void print_tcp_stats_e2e(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  /* End to End flow measures (RTT and TTL) */

 wfprintf (fp, " %f %f %f %f %u %u %u",
   	  (Average (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_count) /
   	   1000.0),
   	  (ptp_save->c2s.rtt_min / 1000.0),
 	  (ptp_save->c2s.rtt_max / 1000.0),
   	  (Stdev (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_sum2,
   		 ptp_save->c2s.rtt_count) / 1000.0),
   	   ptp_save->c2s.rtt_count,
 	   ptp_save->c2s.ttl_min,
 	   ptp_save->c2s.ttl_max);

 wfprintf (fp, " %f %f %f %f %u %u %u",
   	  (Average (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_count) /
   	   1000.0),
   	  (ptp_save->s2c.rtt_min / 1000.0),
 	  (ptp_save->s2c.rtt_max / 1000.0),
   	  (Stdev (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_sum2,
   		 ptp_save->s2c.rtt_count) / 1000.0),
   	   ptp_save->s2c.rtt_count,
 	   ptp_save->s2c.ttl_min,
 	   ptp_save->s2c.ttl_max);
}

void print_tcp_stats_options(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  wfprintf (fp, 
    	   " %d %d %d %d %d %d %u %u %u %u %d %lu %lu %u",
    	   pab->f1323_ws,
    	   pab->f1323_ts,
    	   pab->window_scale,
    	   pab->fsack_req,
    	   pab->sacks_sent,
    	   pab->mss,
    	   pab->max_seg_size,
    	   pab->min_seg_size,
    	   pab->win_max,
    	   pab->win_min,
    	   pab->win_zero_ct,
    	   pab->cwin_max,
    	   pab->cwin_min,
    	   pab->initialwin_bytes);

  wfprintf (fp, " %u %u %u %u %u %u %u %u",
    	   ptp_save->c2s.rtx_RTO,
    	   ptp_save->c2s.rtx_FR,
    	   ptp_save->c2s.reordering,
    	   ptp_save->c2s.net_dup,
    	   ptp_save->c2s.unknown,
    	   ptp_save->c2s.flow_control,
    	   ptp_save->c2s.unnecessary_rtx_RTO,
    	   ptp_save->c2s.unnecessary_rtx_FR);
  /* Bad behaviour */
  wfprintf (fp, " %d", ptp_save->c2s.bad_behavior);

  wfprintf (fp,
    	   " %d %d %d %d %d %d %u %u %u %u %d %lu %lu %u",
    	   pba->f1323_ws,
    	   pba->f1323_ts,
    	   pba->window_scale,
    	   pba->fsack_req,
    	   pba->sacks_sent,
    	   pba->mss,
    	   pba->max_seg_size,
    	   pba->min_seg_size,
    	   pba->win_max,
    	   pba->win_min,
    	   pba->win_zero_ct,
    	   pba->cwin_max, pba->cwin_min, pba->initialwin_bytes);

  wfprintf (fp, " %u %u %u %u %u %u %u %u",
    	   ptp_save->s2c.rtx_RTO,
    	   ptp_save->s2c.rtx_FR,
    	   ptp_save->s2c.reordering,
    	   ptp_save->s2c.net_dup,
    	   ptp_save->s2c.unknown,
    	   ptp_save->s2c.flow_control,
    	   ptp_save->s2c.unnecessary_rtx_RTO,
    	   ptp_save->s2c.unnecessary_rtx_FR);
  /* Bad behaviour */
  wfprintf (fp, " %d", ptp_save->s2c.bad_behavior);
}

void print_tcp_stats_advanced(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba,
                              u_long pab_expected, u_long pba_expected)
{
  /* write to log file */

#ifdef PACKET_STATS
  {
    int i;

     /* PSH-delimited Message sizes */
    wfprintf (fp, " %d",ptp_save->c2s.msg_count);
    for (i=0;i<MAX_COUNT_MESSAGES;i++) {
    	wfprintf (fp, " %d",ptp_save->c2s.msg_size[i]);
     }

    wfprintf (fp, " %d",ptp_save->s2c.msg_count);
    for (i=0;i<MAX_COUNT_MESSAGES;i++) {
    	wfprintf (fp, " %d",ptp_save->s2c.msg_size[i]);
     }

     /* Segment sizes */
    wfprintf (fp, " %d",ptp_save->c2s.seg_count);
    for (i=0;i<MAX_COUNT_SEGMENTS;i++) {
    	wfprintf (fp, " %d",ptp_save->c2s.seg_size[i]);
     }

    wfprintf (fp, " %d",ptp_save->s2c.seg_count);
    for (i=0;i<MAX_COUNT_SEGMENTS;i++) {
    	wfprintf (fp, " %d",ptp_save->s2c.seg_size[i]);
     }

     /* Segment intertimes */
    for (i=0;i<MAX_COUNT_SEGMENTS-1;i++) {
    	wfprintf (fp, " %f",ptp_save->c2s.seg_intertime[i]/1000.);
     }

    for (i=0;i<MAX_COUNT_SEGMENTS-1;i++) {
    	wfprintf (fp, " %f",ptp_save->s2c.seg_intertime[i]/1000.);
     }

#define MEAN(SUM,ENNE) (((ENNE)>0)?((SUM)*1.0/(ENNE)):0.0)
#define VAR(ME,SQ,ENNE) (((ENNE)>1)?((SQ)-(ENNE)*(ME)*(ME))/((ENNE)-1):0.0)

    /* Averages */
     {
       double mval,varval;
       mval = MEAN(ptp_save->c2s.data_bytes,ptp_save->c2s.data_pkts);
       varval = VAR(mval,ptp_save->c2s.data_pkts_sum2,ptp_save->c2s.data_pkts);
       wfprintf (fp, " %d %f %f",ptp_save->c2s.data_pkts,mval,sqrt(varval));

       mval = MEAN(ptp_save->s2c.data_bytes,ptp_save->s2c.data_pkts);
       varval = VAR(mval,ptp_save->s2c.data_pkts_sum2,ptp_save->s2c.data_pkts);
       wfprintf (fp, " %d %f %f",ptp_save->s2c.data_pkts,mval,sqrt(varval));

       mval = MEAN(ptp_save->c2s.seg_intertime_sum,ptp_save->c2s.seg_count-1);
       varval = VAR(mval,ptp_save->c2s.seg_intertime_sum2,ptp_save->c2s.seg_count-1);
       wfprintf (fp, " %d",(ptp_save->c2s.seg_count>1)?ptp_save->c2s.seg_count:0);
       wfprintf (fp, " %f %f",mval/1e3,sqrt(varval)/1e3);

       mval = MEAN(ptp_save->s2c.seg_intertime_sum,ptp_save->s2c.seg_count-1);
       varval = VAR(mval,ptp_save->s2c.seg_intertime_sum2,ptp_save->s2c.seg_count-1);
       wfprintf (fp, " %d",(ptp_save->s2c.seg_count>1)?ptp_save->s2c.seg_count:0);
       wfprintf (fp, " %f %f",mval/1e3,sqrt(varval)/1e3);

     }

    /* PSH */
    wfprintf (fp, " %d %d",ptp_save->c2s.data_pkts_push,
     			   ptp_save->s2c.data_pkts_push);
  }
#endif
}

void print_tcp_stats_layer7(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{

  /* Number of (potential) HTTP Requests and Responses  */
  wfprintf(fp, " %d %d", ptp_save->http_request_count, 
                         ptp_save->http_response_count);

  /* First HTTP response code, if HTTP */
  wfprintf(fp, " %s", (ptp_save->con_type & HTTP_PROTOCOL) ?
                            ptp_save->http_response : "---" );

  /* Number of PSH-separated messages */
  wfprintf(fp," %d %d",ptp_save->c2s.msg_count,ptp_save->s2c.msg_count);

  /* TLS SNI required by the client, if any */
  wfprintf(fp," %s",ptp_save->ssl_client_subject!=NULL?StringEncryptedBase64(ptp_save->ssl_client_subject):"-");

  /* TLS Server Certificate Name SCN, if any */   
  wfprintf(fp," %s",ptp_save->ssl_server_subject!=NULL?StringEncryptedBase64(ptp_save->ssl_server_subject):"-");

  /* TLS NPN / ALPN bitmask recording the usage of SPDY and HTTP2 */
  wfprintf(fp," %d %d",ptp_save->ssl_client_npnalpn, ptp_save->ssl_server_npnalpn);

  /* TLS session-related fields coded as a BitMap
        0000 0000
           ^ ^^^^
           | ||||_____ Client Hello carried a Session ID (Always 1 for TLS 1.3)
           | |||______ Client Hello carried a Pre-Shared Key Extension (only for TLS 1.3)
           | ||_______ Client Hello carried a Early Data Indication Extension (only for TLS 1.3)
           | |________ Server Hello carried a Pre-Shared Key Extension (only for TLS 1.3)
           |__________ Server Hello indicated a Hello Retry Request (only for TLS 1.3)
  */
  u_int16_t reuse_bitmap =   ( ptp_save->ssl_sessionid_reuse ) +
                             ( ptp_save->ssl_client_PSK << 1 ) + 
                             ( ptp_save->ssl_client_early_data << 2 ) + 
                             ( ptp_save->ssl_server_PSK << 3 ) +
                             ( ptp_save->ssl_server_hello_retry << 4 ) ;

  wfprintf(fp," %d", reuse_bitmap);

/* Record time of the end of the SSL handshake */
  
  wfprintf(fp," %f",(ptp_save->con_type & SSL_PROTOCOL?
                     elapsed (ptp_save->first_time,
			      ptp_save->ssl_client_before_data_time) / 1000.0 : 0.0));
  wfprintf(fp," %f",(ptp_save->con_type & SSL_PROTOCOL?
                     elapsed (ptp_save->first_time,
			      ptp_save->ssl_server_before_data_time) / 1000.0 : 0.0));

/* Record time and data before first Application Data in TLS connections */

  wfprintf(fp," %f",(ptp_save->ssl_client_data_seen?
                     elapsed (ptp_save->first_time,
			      ptp_save->ssl_client_data_time) / 1000.0 : 0.0));
  wfprintf(fp," %f",(ptp_save->ssl_server_data_seen?
                     elapsed (ptp_save->first_time,
			      ptp_save->ssl_server_data_time) / 1000.0 : 0.0));


  wfprintf(fp," %lu",(ptp_save->ssl_client_data_seen?
                     (ptp_save->ssl_client_data_byte) : 0L));
  wfprintf(fp," %lu",(ptp_save->ssl_server_data_seen?
                     (ptp_save->ssl_server_data_byte) : 0L));

  if (ptp_save->dns_name!=NULL)
   {
     wfprintf(fp, " %s",StringEncryptedBase64(ptp_save->dns_name));
     /* DNS server */     
     if (ptp_save->crypto_dns==FALSE)
       wfprintf(fp, " %s",HostName(ptp_save->dns_server));
     else
       wfprintf(fp, " %s",HostNameEncrypted(ptp_save->dns_server));
     /* Absolute Request time */
     wfprintf(fp, " %f", time2double(ptp_save->request_time) / 1000.);
      /* Absolute Response time */
     wfprintf(fp, " %f", time2double(ptp_save->response_time) / 1000.);
   }
  else
   {
     wfprintf(fp, " - - 0.0 0.0");
   }
  /* first collected HTTP hostname (from Host:), if any */
  wfprintf(fp," %s",ptp_save->http_hostname!=NULL?StringEncryptedBase64(ptp_save->http_hostname):"-");

  /* TLS Version */
  wfprintf(fp," %s",ptp_save->ssl_client_tls_version!=NULL?ptp_save->ssl_client_tls_version:"-");
  wfprintf(fp," %s",ptp_save->ssl_server_tls_version!=NULL?ptp_save->ssl_server_tls_version:"-");

  // Additional column to indicate if the DNS server address is encrypted
  if (ptp_save->dns_name!=NULL && ptp_save->crypto_dns!=FALSE)
   {
     wfprintf(fp, " 1");
   }
  else
   {
     wfprintf(fp, " 0");
   }

}


void
make_conn_stats (tcp_pair * ptp_save, Bool complete)
{
  tcb *outgoing, *incoming;
  Bool local;
  double etime;
  FILE *fp;
  tcb *pab, *pba;
  u_long pab_expected, pba_expected;

  tcp_cleaned ++;

  print_periodic_log(ptp_save);

  /* Statistics from the plugins */

  /* TCP proto stats should be done only for complete flows 
     This affects only the histograms of L7 TCP flows */
  if (complete)
     make_proto_stat (ptp_save, PROTOCOL_TCP);


  /* TOPIX: connection type statistics */
  if (ptp_save->con_type & RTP_PROTOCOL)
    f_RTP_tunneled_TCP_count++;
  /* end TOPIX */

  pab = &(ptp_save->c2s);
  pba = &(ptp_save->s2c);

  if (ptp_save->internal_src && !ptp_save->internal_dst)
    {
      outgoing = &(ptp_save->c2s);	// c2s out
      incoming = &(ptp_save->s2c);	// s2c in
      local = FALSE;
    }
  else if (ptp_save->internal_dst && !ptp_save->internal_src)
    {
      outgoing = &(ptp_save->s2c);	// s2c out
      incoming = &(ptp_save->c2s);	// c2s in
      local = FALSE;
    }
  else if (ptp_save->internal_src && ptp_save->internal_dst)
    {
      local = TRUE;
      outgoing = &(ptp_save->s2c);	// s2s loc
      incoming = &(ptp_save->c2s);	// c2s loc
    }
  else
    {
      if (warn_IN_OUT)
	{
	  fprintf (fp_stderr, 
        "\nWARN: This flow is neither incoming nor outgoing: src - %s;",
	     HostName (ptp_save->addr_pair.a_address));
	  fprintf (fp_stderr, " dst - %s!\n", HostName (ptp_save->addr_pair.b_address));
	  warn_IN_OUT = FALSE;
	}
      return;
    }


/* Code for sequence_number checking to detect missing packets */ 
   if (pab->max_seq!=pab->syn)
    {
      if ( (pab->fin_count > 0) &&  pab->max_seq > pab->fin_seqno ) 
         pab_expected = pab->max_seq - pab->syn - 2;
      else 
	 pab_expected = pab->max_seq - pab->syn - 1;
    }
   else
    {
      pab_expected = 0;
    }
   
   if (pba->max_seq!=pba->syn)
    {
      if ( (pba->fin_count > 0) &&  pba->max_seq > pba->fin_seqno ) 
	 pba_expected = pba->max_seq - pba->syn - 2;
      else 
	 pba_expected = pba->max_seq - pba->syn - 1;
    }
   else
    {
      pba_expected = 0;
    }

  if (complete)
    {
      /* sack
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.fsack_req && ptp_save->s2c.fsack_req)
	{
	  add_histo (tcp_opts_SACK, 1);
	}
      else if (ptp_save->c2s.fsack_req)
	{
	  add_histo (tcp_opts_SACK, 2);
	}
      else if (ptp_save->s2c.fsack_req)
	{
	  add_histo (tcp_opts_SACK, 3);
	}
      else
	{
	  add_histo (tcp_opts_SACK, 4);
	}

      /* winscale
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.f1323_ws && ptp_save->s2c.f1323_ws)
	{
	  add_histo (tcp_opts_WS, 1);
	}
      else if (ptp_save->c2s.f1323_ws)
	{
	  add_histo (tcp_opts_WS, 2);
	}
      else if (ptp_save->s2c.f1323_ws)
	{
	  add_histo (tcp_opts_WS, 3);
	}
      else
	{
	  add_histo (tcp_opts_WS, 4);
	}


      /* timestamp
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.f1323_ts && ptp_save->s2c.f1323_ts)
	{
	  add_histo (tcp_opts_TS, 1);
	}
      else if (ptp_save->c2s.f1323_ts)
	{
	  add_histo (tcp_opts_TS, 2);
	}
      else if (ptp_save->s2c.f1323_ts)
	{
	  add_histo (tcp_opts_TS, 3);
	}
      else
	{
	  add_histo (tcp_opts_TS, 4);
	}

      /* MultiPath TCP - mptcp
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.mptcp_req && ptp_save->s2c.mptcp_req)
	{
	  add_histo (tcp_opts_MPTCP, 1);
	}
      else if (ptp_save->c2s.mptcp_req)
	{
	  add_histo (tcp_opts_MPTCP, 2);
	}
      else if (ptp_save->s2c.mptcp_req)
	{
	  add_histo (tcp_opts_MPTCP, 3);
	}
      else
	{
	  add_histo (tcp_opts_MPTCP, 4);
	}

      /* MSS
       */

      add_histo (tcp_mss_a, ptp_save->c2s.mss);
      add_histo (tcp_mss_b, ptp_save->s2c.mss);

      if ((ptp_save->c2s.mss == 0) || (ptp_save->s2c.mss == 0))
	{
	  add_histo (tcp_mss_used, 536);
	}
      else if (ptp_save->c2s.mss < ptp_save->s2c.mss)
	{
	  add_histo (tcp_mss_used, ptp_save->c2s.mss);
	}
      else
	{
	  add_histo (tcp_mss_used, ptp_save->s2c.mss);
	}

/* flow lenght */
      if (!local)
	{
	  add_histo (tcp_cl_b_s_out, outgoing->data_bytes);
	  add_histo (tcp_cl_b_s_in, incoming->data_bytes);
	  add_histo (tcp_cl_b_l_out, outgoing->data_bytes);
	  add_histo (tcp_cl_b_l_in, incoming->data_bytes);

	  add_histo (tcp_cl_p_out, outgoing->packets);
	  add_histo (tcp_cl_p_in, incoming->packets);
	}
      else
	{
	  add_histo (tcp_cl_b_s_loc, outgoing->data_bytes);
	  add_histo (tcp_cl_b_s_loc, incoming->data_bytes);
	  add_histo (tcp_cl_b_l_loc, outgoing->data_bytes);
	  add_histo (tcp_cl_b_l_loc, incoming->data_bytes);

	  add_histo (tcp_cl_p_loc, outgoing->packets);
	  add_histo (tcp_cl_p_loc, incoming->packets);
	}

      add_histo (tcp_cl_b_s_c2s, ptp_save->c2s.data_bytes);
      add_histo (tcp_cl_b_s_s2c, ptp_save->s2c.data_bytes);
      add_histo (tcp_cl_b_l_c2s, ptp_save->c2s.data_bytes);
      add_histo (tcp_cl_b_l_s2c, ptp_save->s2c.data_bytes);

      add_histo (tcp_cl_p_c2s, ptp_save->c2s.packets);
      add_histo (tcp_cl_p_s2c, ptp_save->s2c.packets);
      /* receiver window */
      add_histo (tcp_win_min, ptp_save->c2s.win_min);
      add_histo (tcp_win_min, ptp_save->s2c.win_min);


      if (ptp_save->c2s.packets)
	{
	  add_histo (tcp_win_avg,
		     (ptp_save->c2s.win_tot / ptp_save->c2s.packets));
	}
      if (ptp_save->s2c.packets)
	{
	  add_histo (tcp_win_avg,
		     (ptp_save->s2c.win_tot / ptp_save->s2c.packets));
	}

      add_histo (tcp_win_max, ptp_save->c2s.win_max);
      add_histo (tcp_win_max, ptp_save->s2c.win_max);

      /* RTT */

      if ((incoming->rtt_count >= 1) && (outgoing->rtt_count >= 1))
	{
	  if (!local)
	    {
	      add_histo (tcp_rtt_avg_out,
			 (Average (outgoing->rtt_sum, outgoing->rtt_count) /
			  1000.0));
	      add_histo (tcp_rtt_avg_in,
			 (Average (incoming->rtt_sum, incoming->rtt_count) /
			  1000.0));

	      /* min */
	      add_histo (tcp_rtt_min_out, (outgoing->rtt_min / 1000.0));
	      add_histo (tcp_rtt_min_in, (incoming->rtt_min / 1000.0));

	      /* max */
	      add_histo (tcp_rtt_max_out, (outgoing->rtt_max / 1000.0));
	      add_histo (tcp_rtt_max_in, (incoming->rtt_max / 1000.0));

	      /* stdev */
	      add_histo (tcp_rtt_stdev_out,
			 (Stdev (outgoing->rtt_sum, outgoing->rtt_sum2,
				 outgoing->rtt_count) / 1000.0));
	      add_histo (tcp_rtt_stdev_in,
			 (Stdev (incoming->rtt_sum, incoming->rtt_sum2,
				 incoming->rtt_count) / 1000.0));

	      /* valid samples */
	      add_histo (tcp_rtt_cnt_out, outgoing->rtt_count);
	      add_histo (tcp_rtt_cnt_in, incoming->rtt_count);
	    }
	  else 
	    {
	      add_histo (tcp_rtt_avg_loc,
			 (Average (outgoing->rtt_sum, outgoing->rtt_count) /
			  1000.0));
	      add_histo (tcp_rtt_avg_loc,
			 (Average (incoming->rtt_sum, incoming->rtt_count) /
			  1000.0));

	      /* min */
	      add_histo (tcp_rtt_min_loc, (outgoing->rtt_min / 1000.0));
	      add_histo (tcp_rtt_min_loc, (incoming->rtt_min / 1000.0));

	      /* max */
	      add_histo (tcp_rtt_max_loc, (outgoing->rtt_max / 1000.0));
	      add_histo (tcp_rtt_max_loc, (incoming->rtt_max / 1000.0));

	      /* stdev */
	      add_histo (tcp_rtt_stdev_loc,
			 (Stdev (outgoing->rtt_sum, outgoing->rtt_sum2,
				 outgoing->rtt_count) / 1000.0));
	      add_histo (tcp_rtt_stdev_loc,
			 (Stdev (incoming->rtt_sum, incoming->rtt_sum2,
				 incoming->rtt_count) / 1000.0));

	      /* valid samples */
	      add_histo (tcp_rtt_cnt_loc, outgoing->rtt_count);
	      add_histo (tcp_rtt_cnt_loc, incoming->rtt_count);
	    }


	  /* avg */
	  add_histo (tcp_rtt_avg_c2s,
		     (Average (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_count)
		      / 1000.0));
	  add_histo (tcp_rtt_avg_s2c,
		     (Average (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_count)
		      / 1000.0));

	  /* min */
	  add_histo (tcp_rtt_min_c2s, (ptp_save->c2s.rtt_min / 1000.0));
	  add_histo (tcp_rtt_min_s2c, (ptp_save->s2c.rtt_min / 1000.0));

	  /* max */
	  add_histo (tcp_rtt_max_c2s, (ptp_save->c2s.rtt_max / 1000.0));
	  add_histo (tcp_rtt_max_s2c, (ptp_save->s2c.rtt_max / 1000.0));

	  /* stdev */
	  add_histo (tcp_rtt_stdev_c2s,
		     (Stdev (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_sum2,
			     ptp_save->c2s.rtt_count) / 1000.0));
	  add_histo (tcp_rtt_stdev_s2c,
		     (Stdev (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_sum2,
			     ptp_save->s2c.rtt_count) / 1000.0));

	  /* valid samples */
	  add_histo (tcp_rtt_cnt_c2s, ptp_save->c2s.rtt_count);
	  add_histo (tcp_rtt_cnt_s2c, ptp_save->s2c.rtt_count);
	}

      /* Statistichs about duplicates and rtxs */

      if (!local)
	{
	  add_histo (tcp_rtx_RTO_out, outgoing->rtx_RTO);
	  add_histo (tcp_rtx_RTO_in, incoming->rtx_RTO);

	  add_histo (tcp_rtx_FR_out, outgoing->rtx_FR);
	  add_histo (tcp_rtx_FR_in, incoming->rtx_FR);

	  add_histo (tcp_reordering_out, outgoing->reordering);
	  add_histo (tcp_reordering_in, incoming->reordering);

	  add_histo (tcp_net_dup_out, outgoing->net_dup);
	  add_histo (tcp_net_dup_in, incoming->net_dup);

	  add_histo (tcp_unknown_out, outgoing->unknown);
	  add_histo (tcp_unknown_in, incoming->unknown);

	  add_histo (tcp_flow_ctrl_out, outgoing->flow_control);
	  add_histo (tcp_flow_ctrl_in, incoming->flow_control);

	  add_histo (tcp_unnrtx_RTO_out, outgoing->unnecessary_rtx_RTO);
	  add_histo (tcp_unnrtx_RTO_in, incoming->unnecessary_rtx_RTO);

	  add_histo (tcp_unnrtx_FR_out, outgoing->unnecessary_rtx_FR);
	  add_histo (tcp_unnrtx_FR_in, incoming->unnecessary_rtx_FR);
	}
      else
	{
	  add_histo (tcp_rtx_RTO_loc, outgoing->rtx_RTO);
	  add_histo (tcp_rtx_RTO_loc, incoming->rtx_RTO);

	  add_histo (tcp_rtx_FR_loc, outgoing->rtx_FR);
	  add_histo (tcp_rtx_FR_loc, incoming->rtx_FR);

	  add_histo (tcp_reordering_loc, outgoing->reordering);
	  add_histo (tcp_reordering_loc, incoming->reordering);

	  add_histo (tcp_net_dup_loc, outgoing->net_dup);
	  add_histo (tcp_net_dup_loc, incoming->net_dup);

	  add_histo (tcp_unknown_loc, outgoing->unknown);
	  add_histo (tcp_unknown_loc, incoming->unknown);

	  add_histo (tcp_flow_ctrl_loc, outgoing->flow_control);
	  add_histo (tcp_flow_ctrl_loc, incoming->flow_control);

	  add_histo (tcp_unnrtx_RTO_loc, outgoing->unnecessary_rtx_RTO);
	  add_histo (tcp_unnrtx_RTO_loc, incoming->unnecessary_rtx_RTO);

	  add_histo (tcp_unnrtx_FR_loc, outgoing->unnecessary_rtx_FR);
	  add_histo (tcp_unnrtx_FR_loc, incoming->unnecessary_rtx_FR);
	}


      add_histo (tcp_rtx_RTO_c2s, ptp_save->c2s.rtx_RTO);
      add_histo (tcp_rtx_RTO_s2c, ptp_save->s2c.rtx_RTO);

      add_histo (tcp_rtx_FR_c2s, ptp_save->c2s.rtx_FR);
      add_histo (tcp_rtx_FR_s2c, ptp_save->s2c.rtx_FR);

      add_histo (tcp_reordering_c2s, ptp_save->c2s.reordering);
      add_histo (tcp_reordering_s2c, ptp_save->s2c.reordering);

      add_histo (tcp_net_dup_c2s, ptp_save->c2s.net_dup);
      add_histo (tcp_net_dup_s2c, ptp_save->s2c.net_dup);

      add_histo (tcp_unknown_c2s, ptp_save->c2s.unknown);
      add_histo (tcp_unknown_s2c, ptp_save->s2c.unknown);

      add_histo (tcp_flow_ctrl_c2s, ptp_save->c2s.flow_control);
      add_histo (tcp_flow_ctrl_s2c, ptp_save->s2c.flow_control);

      add_histo (tcp_unnrtx_RTO_c2s, ptp_save->c2s.unnecessary_rtx_RTO);
      add_histo (tcp_unnrtx_RTO_s2c, ptp_save->s2c.unnecessary_rtx_RTO);

      add_histo (tcp_unnrtx_FR_c2s, ptp_save->c2s.unnecessary_rtx_FR);
      add_histo (tcp_unnrtx_FR_s2c, ptp_save->s2c.unnecessary_rtx_FR);
    }


  /* connection time and throughput */
  /* from microseconds to ms */
  etime = elapsed (ptp_save->first_time, ptp_save->last_time);
  etime = etime / 1000;

  if (complete)
    {
      double transfer_time, thru;
      
      add_histo (tcp_tot_time, etime);

      transfer_time = elapsed (ptp_save->first_time, pab->payload_end_time);
      
      if (transfer_time > 0.0)
       {
         thru = ((double) ptp_save->c2s.unique_bytes / transfer_time * 8000.0);
        /* throughput in kbps */

	 add_histo (tcp_thru_c2s, thru);
         /* Large flow stats */
	 if ( ptp_save->c2s.unique_bytes >= 1000000)
	  {
	    add_histo (tcp_thru_lf_c2s, thru);
	  }
       }

      transfer_time = elapsed (ptp_save->first_time, pba->payload_end_time);

      if (transfer_time > 0.0)
       {

         thru = ((double) ptp_save->s2c.unique_bytes / transfer_time * 8000.0);

	 add_histo (tcp_thru_s2c, thru);
         /* Large flow stats */
	 if ( ptp_save->s2c.unique_bytes >= 1000000)
	  {
	    add_histo (tcp_thru_lf_s2c, thru);
	  }
       }
    }

  /* check if this flow has been abruptly interrupted by the user       */
  /* according to the heuristic defined in                              */
  /* D. Rossi, C. Casetti, M. Mellia                                    */
  /*      User Patience and the Web: a hands-on investigation           */
  /*      IEEE Globecom 2003                                            */
  /*      San Francisco, CA, USA, December 1-5, 2003                    */
  {
    Bool eligible = !(pba->fin_count > 0 || pba->reset_count > 0)
      && pba->unique_bytes > 0 && pab->reset_count > 0;
    double RTT = Average (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_count) +
      Average (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_count);
    Bool Interrupted = eligible &&
      (elapsed (ptp_save->last_time, pba->payload_end_time) < RTT);
    add_histo (tcp_interrupted, Interrupted);
  }

  /*---------------------------------------------------------*/
  /* dump stream properties                                  */
  /* topix                                                   */

  if (ptp_save->con_type & RTP_PROTOCOL)
    {

      if (!ptp_save->internal_src && ptp_save->internal_dst)
	{
	  add_histo (mm_type_out, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_out, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_out, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_out, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_out,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_out, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_out, pba->packets);
	  add_histo (mm_avg_ipg_out,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_out,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_out, pba->out_order_pkts);
	  add_histo (mm_p_oos_out,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_out, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_out, etime);
	  add_histo (mm_p_dup_out, (pba->rexmit_pkts * 1000) / pba->packets);
	}
      else if (ptp_save->internal_src && !ptp_save->internal_dst)
	{
	  add_histo (mm_type_in, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_in, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_in, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_in, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_in,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_in, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_in, pba->packets);
	  add_histo (mm_avg_ipg_in,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_in,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_in, pba->out_order_pkts);
	  add_histo (mm_p_oos_in,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_in, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_in, etime);
	  add_histo (mm_p_dup_in, (pba->rexmit_pkts * 1000) / pba->packets);
	}
      else if (ptp_save->internal_src && ptp_save->internal_dst)
	{
	  add_histo (mm_type_loc, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_loc, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_loc, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_loc, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_loc,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_loc, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_loc, pba->packets);
	  add_histo (mm_avg_ipg_loc,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_loc,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_loc, pba->out_order_pkts);
	  add_histo (mm_p_oos_loc,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_loc, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_loc, etime);
	  add_histo (mm_p_dup_loc, (pba->rexmit_pkts * 1000) / pba->packets);
	}
      else
	{
	  if (warn_IN_OUT)
	    {
	      fprintf (fp_stderr, 
            "\nWARN: This stream is neither incoming nor outgoing: src - %s;",
		    HostName (ptp_save->addr_pair.a_address));
	      fprintf (fp_stderr, " dst - %s!\n",
		      HostName (ptp_save->addr_pair.b_address));
	      warn_IN_OUT = FALSE;
	    }
	}
    }
  /* end topix */

  /*---------------------------------------------------------*/
  /* RRDtools                                                */
    if (complete) {
        fp = LOG_IS_ENABLED(LOG_TCP_COMPLETE) ? fp_logc : NULL;
    } else {
        fp = LOG_IS_ENABLED(LOG_TCP_NOCOMPLETE) ? fp_lognc : NULL;
    }
  if (fp != NULL)
   {
     /* Core Tstat TCP measurements */
     print_tcp_stats_core(fp, ptp_save, pab, pba);

     /* End to End flow measures (RTT and TTL) */
     if ((log_level & TCP_LOG_END_TO_END) && (complete))
       print_tcp_stats_e2e(fp, ptp_save, pab, pba);

     /* TCP protocol specific information */
     if ((log_level & TCP_LOG_OPTIONS) && (complete))
       print_tcp_stats_options(fp, ptp_save, pab, pba);

     /* TCP Layer7 specific information */
     if ((log_level & TCP_LOG_LAYER7) && (complete))
       print_tcp_stats_layer7(fp, ptp_save, pab, pba);

     /* TCP flow advanced measurements */
     if ((log_level & TCP_LOG_ADVANCED) && (complete))
       print_tcp_stats_advanced(fp, ptp_save, pab, pba, pab_expected, pba_expected);

     wfprintf (fp, "\n");
   }
}

static void
free_tp (tcp_pair * ptp_save)
{
  int i;
  /* free up memory for the flow stats */

  /* for each quad then for each segment in each quad... */
  for (i = 0; i < 4; i++)
    {
      if (ptp_save->c2s.ss->pquad[i] != NULL)
	{
	  freequad (&(ptp_save->c2s.ss->pquad[i]));
	}
    }

  for (i = 0; i < 4; i++)
    {
      if (ptp_save->s2c.ss->pquad[i] != NULL)
	{
	  freequad (&(ptp_save->s2c.ss->pquad[i]));
	}
    }

  /* finally free up the ptp */

  tp_release (ptp_save);
  ptp_save = NULL;

}


void
freequad (quadrant ** ppquad)
{
  segment *pseg;
  segment *pseg_next;

  pseg = (*ppquad)->seglist_head;
  while (pseg && pseg->next)
    {
      pseg_next = pseg->next;
      segment_release (pseg);
      pseg = pseg_next;
    }
  if (pseg)
    segment_release (pseg);

  (*ppquad)->no_of_segments = 0;
  quadrant_release (*ppquad);
  *ppquad = NULL;
}


void print_periodic_log(tcp_pair * ptp_save) {

    /* TUPLE */
    if (!fp_periodic_logc)
      return;
    if (ptp_save->crypto_src==FALSE)
        wfprintf (fp_periodic_logc, "%s", HostName (ptp_save->addr_pair.a_address));
    else
        wfprintf (fp_periodic_logc, "%s", HostNameEncrypted (ptp_save->addr_pair.a_address));

    wfprintf (fp_periodic_logc, " %s", ServiceName (ptp_save->addr_pair.a_port));

    if (ptp_save->crypto_dst==FALSE)
        wfprintf (fp_periodic_logc, " %s", HostName (ptp_save->addr_pair.b_address));
    else
        wfprintf (fp_periodic_logc, " %s", HostNameEncrypted (ptp_save->addr_pair.b_address));

    wfprintf (fp_periodic_logc, " %s", ServiceName (ptp_save->addr_pair.b_port));

    /* TIME */

    wfprintf (fp_periodic_logc, " %f %f %f %f",
              time2double(ptp_save->last_print_time)/1000.0,
              elapsed(ptp_save->first_time, ptp_save->last_print_time)/1000.0,
              elapsed(ptp_save->first_time, ptp_save->last_time)/1000.0,
              elapsed(ptp_save->last_print_time, ptp_save->last_time)/1000.0
             );

    /* Packets and bytes*/

    wfprintf (fp_periodic_logc,
              " %lu %u %lu %lu %lu %lu %lu %u %u %u %d %d",
              ptp_save->c2s.packets - ptp_save->last_print_c2s.packets,
              ptp_save->c2s.reset_count - ptp_save->last_print_c2s.reset_count,
              ptp_save->c2s.ack_pkts - ptp_save->last_print_c2s.ack_pkts,
              ptp_save->c2s.pureack_pkts - ptp_save->last_print_c2s.pureack_pkts,
              ptp_save->c2s.unique_bytes - ptp_save->last_print_c2s.unique_bytes,
              ptp_save->c2s.data_pkts - ptp_save->last_print_c2s.data_pkts,
              ptp_save->c2s.data_bytes - ptp_save->last_print_c2s.data_bytes,
              ptp_save->c2s.rexmit_pkts - ptp_save->last_print_c2s.rexmit_pkts,
              ptp_save->c2s.rexmit_bytes - ptp_save->last_print_c2s.rexmit_bytes,
              ptp_save->c2s.out_order_pkts - ptp_save->last_print_c2s.out_order_pkts,
              ptp_save->c2s.syn_count - ptp_save->last_print_c2s.syn_count,
              ptp_save->c2s.fin_count - ptp_save->last_print_c2s.fin_count);

    wfprintf (fp_periodic_logc,
              " %lu %u %lu %lu %lu %lu %lu %u %u %u %d %d",
              ptp_save->s2c.packets - ptp_save->last_print_s2c.packets,
              ptp_save->s2c.reset_count - ptp_save->last_print_s2c.reset_count,
              ptp_save->s2c.ack_pkts - ptp_save->last_print_s2c.ack_pkts,
              ptp_save->s2c.pureack_pkts - ptp_save->last_print_s2c.pureack_pkts,
              ptp_save->s2c.unique_bytes - ptp_save->last_print_s2c.unique_bytes,
              ptp_save->s2c.data_pkts - ptp_save->last_print_s2c.data_pkts,
              ptp_save->s2c.data_bytes - ptp_save->last_print_s2c.data_bytes,
              ptp_save->s2c.rexmit_pkts - ptp_save->last_print_s2c.rexmit_pkts,
              ptp_save->s2c.rexmit_bytes - ptp_save->last_print_s2c.rexmit_bytes,
              ptp_save->s2c.out_order_pkts - ptp_save->last_print_s2c.out_order_pkts,
              ptp_save->s2c.syn_count - ptp_save->last_print_s2c.syn_count,
              ptp_save->s2c.fin_count - ptp_save->last_print_s2c.fin_count);

    /* RTT */
    wfprintf (fp_periodic_logc,
              " %f %u",
              Average(ptp_save->c2s.rtt_sum   - ptp_save->last_print_c2s.rtt_sum,
                      ptp_save->c2s.rtt_count - ptp_save->last_print_c2s.rtt_count) / 1000.0 ,
              ptp_save->c2s.rtt_count  - ptp_save->last_print_c2s.rtt_count);

    wfprintf (fp_periodic_logc,
              " %f %u",
              Average(ptp_save->s2c.rtt_sum   - ptp_save->last_print_s2c.rtt_sum ,
                      ptp_save->s2c.rtt_count - ptp_save->last_print_s2c.rtt_count) / 1000.0,
              ptp_save->s2c.rtt_count  - ptp_save->last_print_s2c.rtt_count);

    /*  Congestion Window*/
    wfprintf (fp_periodic_logc,
              " %u %u %u %u",
              ptp_save->c2s.cwin_min_periodic,
              ptp_save->c2s.cwin_max_periodic,
              ptp_save->s2c.cwin_min_periodic,
              ptp_save->s2c.cwin_max_periodic);

    /* SACKs sent */
    wfprintf (fp_periodic_logc,
              " %u %u",
              ptp_save->c2s.sacks_sent - ptp_save->last_print_c2s.sacks_sent,
              ptp_save->s2c.sacks_sent - ptp_save->last_print_s2c.sacks_sent);

    /* printing boolean flag if source is considered internal or not */
    wfprintf (fp_periodic_logc, " %d", ptp_save->internal_src);
    /* printing boolean flag if destination is considered internal or not */
    wfprintf (fp_periodic_logc, " %d", ptp_save->internal_dst);

    /* printing boolean flag if source is anonymized or not */
    wfprintf (fp_periodic_logc, " %d", ptp_save->crypto_src);
    /* printing boolean flag if destination is anonymized or not */
    wfprintf (fp_periodic_logc, " %d", ptp_save->crypto_dst);

    /* new line */
    wfprintf (fp_periodic_logc, "\n");

    /*update counters*/
    ptp_save->last_print_time = current_time; //ptp_save->last_time;
    ptp_save->last_print_c2s = ptp_save->c2s;
    ptp_save->last_print_s2c = ptp_save->s2c;

    ptp_save->c2s.cwin_min_periodic = 0;
    ptp_save->c2s.cwin_max_periodic = 0;

    ptp_save->s2c.cwin_min_periodic = 0;
    ptp_save->s2c.cwin_max_periodic = 0;

}

