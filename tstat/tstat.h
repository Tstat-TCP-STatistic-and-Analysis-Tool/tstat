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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <math.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


/* IPv6 support */
#include "ipv6.h"

#include "param.h"
#include "l7types.h"
#include "struct.h"
/* include the histo management functions and declaration */
#include "histo.h"

#include "rtp.h"
#include "freelists.h"
#include "rrdtool.h"
#include "plugin.h"
#include "protocol.h"
#include "dump.h"
#include "inireader.h"
#include "dns_namefilter.h"
#include "names.h"
#include "crypto.h"
#include "../include/libtstat.h"

#define min(x,y) (((x)<(y))?(x):(y))
#define max(x,y) (((x)>(y))?(x):(y))


/* fixed size integer types, used to access packet header fields */
typedef uint32_t tt_uint32;
typedef int32_t tt_int32;
typedef uint16_t tt_uint16;
typedef int16_t tt_int16;
typedef uint8_t tt_uint8;

#define FILENAME_SIZE 600
/* declaration of global variables */
// extern char runtime_conf_fname[];
extern int num_udp_pairs;	/* how many pairs are in use */
extern udp_pair **utp;		/* array of pointers to allocated pairs */


/* option flags */
extern Bool internal_src;
extern Bool internal_dst;

extern Bool crypto_src;
extern Bool crypto_dst;

extern Bool warn_ooo;
extern Bool warn_IN_OUT;
extern Bool warn_printtrunc;
extern Bool warn_printbadmbz;
extern Bool warn_printbad_syn_fin_seq;
extern Bool save_tcp_data;
extern Bool do_udp;
extern int debug;
extern u_long pnum;

extern u_long ctrunc;
extern timeval current_time;

/* first and last packet timestamp */
extern timeval first_packet;
extern timeval last_packet;

/* global routine decls */

void *MallocZ (int);
void trace_init (void);
void tcp_header_stat (struct tcphdr *ptcp, struct ip *pip, void *plast);
int tcp_flow_stat (struct ip *, struct tcphdr *ptcp, void *plast,
			 int *dir);
double elapsed (timeval, timeval);
int tv_cmp (struct timeval lhs, struct timeval rhs);
char *elapsed2str (double etime);
double Average (double sum, int count);
double Stdev (double sum, double sum2, int n);
char *ts2ascii (timeval *);
char *ServiceName (portnum);
char *HostName (ipaddr);
char *HostAddr (ipaddr);
char * Timestamp (void);
int rexmit (tcb * ptcb, seqnum seq, seglen len, Bool * pout_order,
	    u_short this_ip_id);
enum t_ack ack_in (tcb *, seqnum, unsigned tcp_data_length);
struct tcp_options *ParseOptions (struct tcphdr *ptcp, void *plast);

void IP_COPYADDR (ipaddr * toaddr, ipaddr fromaddr);
int IP_SAMEADDR (ipaddr addr1, ipaddr addr2);
void StringToArgv (char *buf, int *pargc, char ***pargv);
void CopyAddr (tcp_pair_addrblock *, struct ip *pip, portnum, portnum);
int WhichDir (tcp_pair_addrblock *, tcp_pair_addrblock *);
int SameConn (tcp_pair_addrblock *, tcp_pair_addrblock *, int *);

/* UDP support routines */
void udptrace_init (void);
void udptrace_done (void);
void udp_header_stat (struct udphdr *pudp, struct ip *pip, void *plast);
int udp_flow_stat (struct ip *pip, struct udphdr *pudp, void *plast);
void close_udp_flow (udp_pair * pup, int ix, int dir);

/* TCP flags macros */
#define SYN_SET(ptcp)((ptcp)->th_flags & TH_SYN)
#define FIN_SET(ptcp)((ptcp)->th_flags & TH_FIN)
#define ACK_SET(ptcp)((ptcp)->th_flags & TH_ACK)
#define RESET_SET(ptcp)((ptcp)->th_flags & TH_RST)
#define PUSH_SET(ptcp)((ptcp)->th_flags & TH_PUSH)
#define URGENT_SET(ptcp)((ptcp)->th_flags & TH_URG)
#define FLAG6_SET(ptcp)((ptcp)->th_flags & 0x40)
#define FLAG7_SET(ptcp)((ptcp)->th_flags & 0x80)
#define CWR_SET(ptcp)((ptcp)->th_x2 & TH_CWR)
#define ECN_ECHO_SET(ptcp)((ptcp)->th_x2 & TH_ECN_ECHO)

/* connection directions.
	for hyper_histo:
	network and flow directions
	v1.2.0
*/


#define C2S 1
#define S2C -1

#define OUT_FLOW 1
#define IN_FLOW 2
#define LOC_FLOW 3
#define EXT_FLOW 4


/*macros for maintaining the seqspace used for rexmit*/
#define QUADSIZE	(0x40000000)
#define QUADNUM(seq)	((seq>>30)+1)
#define IN_Q1(seq)	(QUADNUM(seq)==1)
#define IN_Q2(seq)	(QUADNUM(seq)==2)
#define IN_Q3(seq)	(QUADNUM(seq)==3)
#define IN_Q4(seq)	(QUADNUM(seq)==4)
#define FIRST_SEQ(quadnum)	(QUADSIZE*(quadnum-1))
#define LAST_SEQ(quadnum)	((QUADSIZE-1)*quadnum)
#define BOUNDARY(beg,fin) (QUADNUM((beg)) != QUADNUM((fin)))


/* physical layers currently understood					*/
#define PHYS_ETHER	1
#define PHYS_FDDI       2

/*
 * SEQCMP - sequence space comparator
 *	This handles sequence space wrap-around. Overlow/Underflow makes
 * the result below correct ( -, 0, + ) for any a, b in the sequence
 * space. Results:	result	implies
 *			  - 	 a < b
 *			  0 	 a = b
 *			  + 	 a > b
 */
#define	SEQCMP(a, b)		((long)(a) - (long)(b))
#define	SEQ_LESSTHAN(a, b)	(SEQCMP(a,b) < 0)
#define	SEQ_GREATERTHAN(a, b)	(SEQCMP(a,b) > 0)


/* SACK TCP options (not an RFC yet, mostly from draft and RFC 1072) */
/* I'm assuming, for now, that the draft version is correct */
/* sdo -- Tue Aug 20, 1996 */
#define	TCPOPT_SACK_PERM 4	/* sack-permitted option */
#define	TCPOPT_SACK      5	/* sack attached option */
#define	MAX_SACKS       10	/* max number of sacks per segment (rfc1072) */
typedef struct sack_block
{
  seqnum sack_left;		/* left edge */
  seqnum sack_right;		/* right edge */
}
sack_block;


/* MultiPath TCP - mptcp - option - RFC 6824 */
#define TCPOPT_MPTCP 30 /* mptcp option number as assigned by IANA */

#define MAX_UNKNOWN 16
typedef struct opt_unknown
{
  u_char unkn_opt;
  u_char unkn_len;
}
opt_unknown;

/* RFC 1323 TCP options (not usually in tcp.h yet) */
#define	TCPOPT_WS	3	/* window scaling */
#define	TCPOPT_TS	8	/* timestamp */

/* other options... */
#define	TCPOPT_ECHO		6	/* echo (rfc1072) */
#define	TCPOPT_ECHOREPLY	7	/* echo (rfc1072) */
#define TCPOPT_TIMESTAMP	8	/* timestamps (rfc1323) */
#define TCPOPT_CC		11	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCNEW		12	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCECHO		13	/* T/TCP CC options (rfc1644) */

/* RFC 2481 (ECN) IP and TCP flags (not usually defined yet) */
#define IPTOS_ECT	0x02	/* ECN-Capable Transport */
#define IPTOS_CE	0x01	/* Experienced Congestion */

#define TH_ECN_ECHO	0x02	/* Used by receiver to echo CE bit */
#ifndef TH_CWR
#define TH_CWR		0x01	/* Congestion Window Reduced */
#endif


/* some compilers seem to want to make "char" unsigned by default, */
/* which is breaking stuff.  Rather than introduce (more) ugly */
/* machine dependencies, I'm going to FORCE some chars to be */
/* signed... */
typedef signed char s_char;

struct tcp_options
{
  short mss;			/* maximum segment size         */
  s_char ws;			/* window scale (1323)          */
  long tsval;			/* Time Stamp Val (1323)        */
  long tsecr;			/* Time Stamp Echo Reply (1323) */

  Bool sack_req;		/* sacks requested              */
  s_char sack_count;		/* sack count in this packet */
  sack_block sacks[MAX_SACKS];	/* sack blocks */

  Bool mptcp_req;		/* mptcp requested              */

  /* echo request and reply */
  /* assume that value of -1 means unused  (?) */
  u_long echo_req;
  u_long echo_repl;

  /* T/TCP stuff */
  /* assume that value of -1 means unused  (?) */
  u_long cc;
  u_long ccnew;
  u_long ccecho;

  /* record the stuff we don't understand, too */
  char unknown_count;		/* number of unknown options */
  opt_unknown unknowns[MAX_UNKNOWN];	/* unknown options */
};


/* packet-reading options... */
/* the type for a packet reading routine */
typedef int pread_f (struct timeval *, int *, int *, void **,
		     int *, struct ip **, void **);

/* packet readers: pcap/pcapng files and live capture through libpcap */
pread_f *is_tcpdump (char *);
pread_f *init_live_tcpdump (char *);
int
pread_tcpdump (struct timeval *ptime,
	       int *plen,
	       int *ptlen,
	       void **pphys, int *pphystype, struct ip **ppip, void **pplast);

char ** ArgsFromFile(char *fname, int *pargc);

#ifndef EOL
#define EOL          0xa
#endif
extern Bool net_conf;
/*------------------* v1.2.0 *----------------------*/


/*
 * timeval compare macros
 */
#define tv_ge(lhs,rhs) (tv_cmp((lhs),(rhs)) >= 0)
#define tv_gt(lhs,rhs) (tv_cmp((lhs),(rhs)) >  0)
#define tv_le(lhs,rhs) (tv_cmp((lhs),(rhs)) <= 0)
#define tv_lt(lhs,rhs) (tv_cmp((lhs),(rhs)) <  0)
#define tv_eq(lhs,rhs) (tv_cmp((lhs),(rhs)) == 0)

/* handy constants */
#define US_PER_SEC 1000000	/* microseconds per second */
#define MS_PER_SEC 1000		/* milliseconds per second */


/*
 * Macros to simplify access to IPv4/IPv6 header fields
 */
#define PIP_VERS(pip) (((struct ip *)(pip))->ip_v)
#define PIP_ISV6(pip) (PIP_VERS(pip) == 6)
#define PIP_ISV4(pip) (PIP_VERS(pip) == 4)
#define PIP_V6(pip) ((struct ipv6 *)(pip))
#define PIP_V4(pip) ((struct ip *)(pip))
#define PIP_EITHERFIELD(pip,fld4,fld6) \
   (PIP_ISV4(pip)?(PIP_V4(pip)->fld4):(PIP_V6(pip)->fld6))
#define PIP_LEN(pip) (PIP_EITHERFIELD(pip,ip_len,ip6_lngth))

/*
 * Macros to simplify access to IPv4/IPv6 addresses
 */
#define ADDR_VERSION(paddr) ((paddr)->addr_vers)
#define ADDR_ISV4(paddr) (ADDR_VERSION((paddr)) == 4)
#define ADDR_ISV6(paddr) (ADDR_VERSION((paddr)) == 6)
struct ipaddr *IPV4ADDR2ADDR (struct in_addr *addr4);
struct ipaddr *IPV6ADDR2ADDR (struct in6_addr *addr6);

/*
 * Macros to check for congestion experienced bits
 */
#define IP_CE(pip) (((struct ip *)(pip))->ip_tos & IPTOS_CE)
#define IP_ECT(pip) (((struct ip *)(pip))->ip_tos & IPTOS_ECT)

/*
 * constants not always defined by the system headers
 */
#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif /* IP_MAXPACKET */

#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035
#endif /* ETHERTYPE_REVARP */

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN		0x8100
#endif /* 802.1Q Virtual LAN */

#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q 0x8100	/* Ethernet type for VLAN */
#endif

/* support for vlan tagging */
#ifndef IEEE8021Q_SIZE
#define IEEE8021Q_SIZE		18
#endif /* VLAN header size */

/* support for MPLS over ETH */
#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS	0x8847
#endif /* MPLS ether type */

#ifndef MPLS_SIZE
#define MPLS_SIZE		18
#endif /* MPLS over ETH header size */

#ifndef MPLS8021Q_SIZE
#define MPLS8021Q_SIZE		22
#endif /* MPLS over VLAN header size */

/* support for PPPoE encapsulation added by Yann Samama (ysamama@nortelnetworks.com)*/
#ifndef ETHERTYPE_PPPOE_SESSION
#define ETHERTYPE_PPPOE_SESSION	0x8864
#endif /* PPPoE ether type */
#ifndef PPPOE_SIZE
#define PPPOE_SIZE		22
#endif /* PPPOE header size */

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD	/* Ethernet type for ipv6 */
#endif


#define TCP_TYPE        0
#define UDP_TYPE        1
#define ICMP_TYPE       2
#define IP_TYPE         3


/* Return Values for tcp_flow_stat() and udp_flow_stat() */
#define FLOW_STAT_NULL  0
#define FLOW_STAT_OK    1
#define FLOW_STAT_DUP   2
#define FLOW_STAT_NONE  3
#define FLOW_STAT_SHORT 4

/* LM start- possible classification of out of order and retransmission */
#define IN_SEQUENCE			0
#define RETRANSMISSION_RTO   		1
#define RETRANSMISSION_FR  		2
#define REORDERING			3
#define NETWORK_DUPLICATE		4
#define FLOW_CONTROL			5
#define UNNECESSARY_RETRANSMISSION_RTO	6
#define UNNECESSARY_RETRANSMISSION_FR	7

#define DUPLICATE_WITH_RC_LESS_THAN_RTT_NOT_3DUP_ACK   8
#define DUPLICATE_WITH_RC_LESS_THAN_RTO_AND_GREATER_THAN_RTT_NOT_3DUP_ACK 9

#define OOO_WITH_RC_LESS_THAN_RTT_NOT_3DUP_ACK 10
#define OOO_WITH_RC_LESS_THAN_RTO_AND_GREATER_THAN_RTT_NOT_3DUP_ACK 11

#define UNNECESSARY_RETRANSMISSION_WITH_RC_LESS_THAN_RTT_NOT_3DUP_ACK 12
#define UNNECESSARY_RETRANSMISSION_WITH_RC_LESS_THAN_RTO_AND_GREATER_THAN_RTT_NOT_3DUP_ACK 13

#define NUM_TCP_ANOMALIES 64
/* for compatibility - should never be used */
#define UNKNOWN           (NUM_TCP_ANOMALIES - 1)

#define BATCH_CLASSIFICATION 16
#define NO_RTT_SAMPLE_CLASSIFICATION 32

/* define the minimum rto [microsecond] */
#define RTO_MIN 100000
#define RTT_MIN 1000

#define INITIAL_RTO 500000
#define INITIAL_RTT_MIN 5000

#define CLASSIFICATION(X) ( (validRTT) ? X : (X | NO_RTT_SAMPLE_CLASSIFICATION) )

#define ANSI_BOLD    "\x1b[1m"
#define ANSI_RESET   "\x1b[0m"

/* LM stop */

extern char runtime_conf_fname[];
extern timeval last_time_step;
extern timeval last_cleaned;

extern Bool runtime_engine;
extern Bool rrd_engine;
extern Bool con_cat;
extern FILE *fp_stdout;
extern FILE *fp_stderr;
extern Bool redirect_output; 
extern char *outdir_basename;

extern unsigned long tot_conn_TCP;
extern unsigned long tot_conn_UDP;
void trace_done_periodic ();
void freequad (quadrant ** ppquad);

void make_conn_stats (tcp_pair * ptp_save, Bool flusso_nc);
void make_udp_conn_stats (udp_pair * pup_save, Bool flusso_nc);
void trace_done (void);
void tcpdump_cleanup (FILE * wheref);
char *url_encode (char *str);

extern int wfprintf(FILE *stream, const char* format, ... );

/* misc.c */

int in_out_loc (int internal_src, int internal_dst, int dir);

/* DNS Plugin */

void dns_cache_init();
void *check_dns_response(struct udphdr *pudp, int tproto, void *pdir, void *plast);
void dns_process_response(struct ip *pip, void *pproto, int tproto, void *pdir, 
                          int dir, void *hdr, void *plast);
void dns_cache_status(void *thisdir, int tproto);

/* HTTP Plugin */

void http_init ();
void *gethttp (struct udphdr *pudp, int tproto, void *pdir, void *plast);
void http_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast);
void make_http_conn_stats (void * thisdir, int tproto);

/* tcpL7 */
void tcpL7_init ();
void *gettcpL7 (struct udphdr *pudp, int tproto, void *pdir, void *plast);
void tcpL7_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast);
void make_tcpL7_conn_stats (void * thisdir, int tproto);
void make_tcpL7_rate_stats (tcp_pair *thisflow, int len);
void make_udpL7_rate_stats (ucb * thisflow, int len);

/* udpL7 */
void *getudpL7 (struct udphdr *pudp, int tproto, void *pdir, void *plast);
void udpL7_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast);
void make_udpL7_conn_stats (void * thisflow, int tproto);
int udp_to_L7type (ucb *thisflow);

/* DNS log */
void * check_dns(struct udphdr *pudp, int tproto, void *pdir, void *plast);
void dns_flow_stat(struct ip *pip, void *pproto, int tproto, void *pdir, int dir, void *hdr, void *plast);

/* web */

tstat_report * get_stats_report(tstat_report *report);

void log_parse_ini_arg(char *param_name, param_value param_value);
void log_parse_end_section(void);
void log_parse_start_section(void);

Bool internal_ip (struct in_addr adx);
Bool crypto_ip (struct in_addr adx);

extern  long log_bitmask;
#define LOG_IS_ENABLED(VAL)     (((log_bitmask & VAL) > 0))
#define LOG_TCP_COMPLETE        0x0001
#define LOG_TCP_NOCOMPLETE      0x0002
#define LOG_UDP_COMPLETE        0x0004
#define LOG_MM_COMPLETE         0x0008
// other logs disabled by default
#define LOG_HTTP_COMPLETE       0x0200
#define LOG_DNS_COMPLETE        0x0400
#define LOG_TCP_PERIODIC        0x0800
#define LOG_UDP_PERIODIC        0x1000
// logs enabled by default
#define LOG_ALL                 (LOG_TCP_COMPLETE|LOG_TCP_NOCOMPLETE|LOG_UDP_COMPLETE|LOG_MM_COMPLETE)

#define TCP_LOG_CORE		0x0000
#define TCP_LOG_END_TO_END	0x0001
#define TCP_LOG_LAYER7		0x0002
#define TCP_LOG_OPTIONS		0x0008
#define TCP_LOG_ADVANCED	0x0010
#define TCP_LOG_ALL		(TCP_LOG_END_TO_END|TCP_LOG_LAYER7|TCP_LOG_OPTIONS)

extern struct global_parameters GLOBALS;
