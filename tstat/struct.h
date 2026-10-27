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

typedef unsigned long long int u_llong;
typedef long long int llong;

/* type for a TCP sequence number, ACK, FIN, or SYN */
typedef u_int32_t seqnum;

/* length of a segment */
typedef u_long seglen;

/* type for a quadrant number */
typedef u_char quadnum;		/* 1,2,3,4 */

/* type for a TCP port number */
typedef u_short portnum;

/* type for an IP address */
/* IP address can be either IPv4 or IPv6 */
typedef struct ipaddr
{
  u_char addr_vers;		/* 4 or 6 */
  union
  {
    struct in_addr ip4;
    struct in6_addr ip6;
  }
  un;
}
ipaddr;


/* type for a timestamp */
typedef struct timeval timeval;
#define ZERO_TIME(ptv)(((ptv)->tv_sec == 0) && ((ptv)->tv_usec == 0))
#define time2double(t) ((double) (t).tv_sec * 1000000 + (double) (t).tv_usec)

/* type for a Boolean */
typedef u_char Bool;
#define TRUE	1
#define FALSE	0
#define BOOL2STR(b) (b)?"TRUE":"FALSE"

/* ACK types */
enum t_ack
{ NORMAL = 1,			/* no retransmits, just advance */
  AMBIG = 2,			/* segment ACKed was rexmitted */
  CUMUL = 3,			/* doesn't advance */
  TRIPLE = 4,			/* triple dupack */
  NOSAMP = 5
};				/* covers retransmitted segs, no rtt sample */

extern unsigned long int fcount;	/* total flow number number */

/* first and last packet timestamp */
extern timeval first_packet;
extern timeval last_packet;

/* counters */
// LM
extern u_long tcp_trace_count_outgoing;
extern u_long tcp_trace_count_incoming;
extern u_long tcp_trace_count_local;
extern u_long udp_trace_count;

/* incoming/outgoing based on Ethernet MAC addresses */
typedef struct eth_filter
{
  int tot_internal_eth;
  // uint8_t addr[MAX_INTERNAL_ETHERS][6];
  uint8_t **addr;
} eth_filter;

typedef struct segment
{
  seqnum seq_firstbyte;		/* seqnumber of first byte */
  seqnum seq_lastbyte;		/* seqnumber of last byte */
  u_char retrans;		/* retransmit count */
  u_int acked;			/* how MANY times has has it been acked? */
  timeval time;			/* time the segment was sent */
  /* LM start - add field to implement an heuristic to identify 
     loss packets within a flow
   */
  u_short ip_id;		/* 16 bit ip identification field  */
  char type_of_segment;
  /* LM stop */
  struct segment *next;
  struct segment *prev;
}
segment;

typedef struct quadrant
{
  segment *seglist_head;
  segment *seglist_tail;
  Bool full;
  u_long no_of_segments;
  struct quadrant *prev;
  struct quadrant *next;
}
quadrant;

typedef struct seqspace
{
  quadrant *pquad[4];
}
seqspace;

typedef struct upper_protocols
{
  timeval f_http;
  timeval f_rtsp;
  timeval f_rtp;
} upper_protocols;

/* Only store the size for the first 4 messages */
#define MAX_COUNT_MESSAGES 10
#ifdef PACKET_STATS
#define MAX_COUNT_SEGMENTS 10
#endif

typedef struct tcb
{
  /* parent pointer */
  struct stcp_pair *ptp;

  seqnum highest_seqno;		/* to identify the end of the data */
  Bool data_to_be_acked;	/* true if waiting for an ack */
  timeval payload_start_time;	/* time of first data pkt ... */
  timeval payload_end_time;	/* time of last valid ack... */
  timeval ack_start_time;	/* time of first ack (not syn) */

  /* TCP information */
  seqnum ack;
  seqnum seq;
  seqnum syn;
  seqnum fin;
  seqnum fin_seqno;
  seqnum windowend;
  timeval time;

  /* TCP options */
  u_int mss;
  Bool f1323_ws;		/* did he request 1323 window scaling? */
  Bool f1323_ts;		/* did he request 1323 timestamps? */
  Bool fsack_req;		/* did he request SACKs? */
  Bool mptcp_req;		/* did he request MPTCP? */
  u_char window_scale;

  /* statistics added */
  u_long ip_bytes;		/* bytes (Hdr IP + Payload IP) sent including SYN-FIN and rexmits */
  u_long data_bytes;
  u_long data_pkts;
  u_long data_pkts_push;
  u_long unique_bytes;		/* bytes sent (-FIN/SYN), excluding rexmits */
  u_int rexmit_bytes;
  u_int rexmit_pkts;
  u_long ack_pkts;
  u_long pureack_pkts;		/* mallman - pure acks, no data */
  u_int win_max;
  u_int win_min;
  u_int win_tot;
  u_int win_curr;
  u_int win_zero_ct;
  u_int max_seq;
  u_long packets;
  u_char syn_count;
  u_char fin_count;
  Bool closed;
  u_char reset_count;		/* resets SENT */
  u_int min_seg_size;
  u_int max_seg_size;
  u_int out_order_pkts;		/* out of order packets */
  u_int sacks_sent;		/* sacks returned */

  /* .a.c. cwnd stats */
  u_int cwnd_max;
  u_int cwnd_flag;

  /* did I detect any "bad" tcp behavior? */
  /* at present, this means: */
  /*  - SYNs retransmitted with different sequence numbers */
  /*  - FINs retransmitted with different sequence numbers */
  Bool bad_behavior;

  /* added for initial window stats (for Mallman) */
  u_int initialwin_bytes;	/* initial window (in bytes) */
  u_int initialwin_segs;	/* initial window (in segments) */
  Bool data_acked;		/* has any non-SYN data been acked? */

  /* added for (estimated) congestions window stats (for Mallman) */
  u_long cwin_max;
  u_long cwin_min;

  u_long cwin_max_periodic;
  u_long cwin_min_periodic;

  /* RTT stats for singly-transmitted segments */
  double rtt_last;		/* RTT as of last good ACK (microseconds) */
  u_long rtt_min;
  u_long rtt_max;
  double rtt_sum;		/* for averages */
  double rtt_sum2;		/* sum of squares, for stdev */
  double srtt;			/* smoothed RTT estimation */
  double rttvar;		/* smoothed stdv estimation */
  u_int rtt_count;		/* for averages */
/* MGM */
  /* Duplicated and rtx counters */
  u_int rtx_RTO;
  u_int rtx_FR;
  u_int reordering;
  u_int net_dup;
  u_int unknown;
  u_int flow_control;
  u_int unnecessary_rtx_FR;
  u_int unnecessary_rtx_RTO;
    /*LM*/ u_int ttl_min;
  u_int ttl_max;
  /* TOPIX */
  u_llong ttl_tot;
  double sum_jitter;
  float max_jitter;
  float min_jitter;
  double sum_delta_t;
  int n_delta_t;
  /* end TOPIX */

  /* ACK Counters */
  u_long rtt_cumack;		/* segments only cumulativly ACKed */
  u_long rtt_nosample;		/* segments ACKED, but after retransmission */
  /* of earlier segments, so sample isn't */
  /* valid */
  u_long rtt_unkack;		/* unknown ACKs  ??? */
  u_long rtt_dupack;		/* duplicate ACKs */
  u_long rtt_triple_dupack;	/* triple duplicate ACKs */
  /* retransmission information */
  seqspace *ss;			/* the sequence space */
  u_long retr_max;		/* maximum retransmissions ct */
  u_long retr_min_tm;		/* minimum retransmissions time */
  u_long retr_max_tm;		/* maximum retransmissions time */
  double retr_tm_sum;		/* for averages */
  double retr_tm_sum2;		/* sum of squares, for stdev */
  u_long retr_tm_count;		/* for averages */

  /* data transfer time stamps - mallman */
  timeval first_data_time;
  timeval last_data_time;


  /* for tracking unidirectional idle time */
  timeval last_time;		/* last packet SENT from this side */

  upper_protocols u_protocols;

  /* Count TCP messages, as separated by PSH or FIN*/
  seqnum msg_last_seq;
  u_int msg_count;
  u_int msg_size[MAX_COUNT_MESSAGES];

  /* Store information on the first MAX_COUNT_SEGMENTS segments */
#ifdef PACKET_STATS
  u_int seg_count;
  u_int seg_size[MAX_COUNT_SEGMENTS];
  double last_seg_time;
  double seg_intertime[MAX_COUNT_SEGMENTS];
  double data_pkts_sum2;
  double seg_intertime_sum;
  double seg_intertime_sum2;
#endif
}
tcb;


typedef u_long hash;

typedef struct
{
  ipaddr a_address;
  ipaddr b_address;
  portnum a_port;
  portnum b_port;
  hash hash;
}
tcp_pair_addrblock;

enum state_type
{ UNKNOWN_TYPE = 0,
  RTSP_COMMAND,
  RTSP_RESPONSE,
  HTTP_COMMAND,
  HTTP_RESPONSE,
  SMTP_OPENING,
  POP3_OPENING,
  IMAP_OPENING,
  IMAP_COMMAND,
  SSL_HANDSHAKE,
  SSL_DATA,
  SSH_SERVER,
  RTMP_HANDSHAKE,
  IGNORE_FURTHER_PACKETS
};

enum npnalpn {
    TLS_EMPTY  =   0,
    NPN_EMPTY  =   1,
    NPN_HTTP   =   2,
    NPN_SPDY   =   4,
    NPN_H2     =   8,
    ALPN_EMPTY =  16,
    ALPN_HTTP  =  32,
    ALPN_SPDY  =  64,
    ALPN_H2    = 128,
};

enum l3_category
{
  L3_IPv4_TCP,
  L3_IPv4_UDP,
  L3_IPv4_OTHER,
  L3_IPv6_TCP,
  L3_IPv6_UDP,
  L3_IPv6_OTHER,
  L3_LAST_TYPE
};

struct stcp_pair
{

  /* endpoint identification */
  tcp_pair_addrblock addr_pair;

  /* connection naming information */
  Bool internal_src;
  Bool internal_dst;

  /* connection information */
  unsigned long int id_number;
  timeval first_time;
  timeval last_time;
  u_long packets;
  tcb c2s;
  tcb s2c;

  /* layer 7 classification */
  u_int32_t con_type;
  enum state_type state;
  unsigned char rtp_pt;
  int  http_request_count;
  int  http_response_count;
  int  http_request_status;
  int  http_response_status;
  int  http_request_fragment;
  int  http_response_fragment;
  char http_response[4];
  char *http_hostname;

  /* rtmp identification */
  unsigned state_rtmp_c2s_seen:1;
  unsigned state_rtmp_s2c_seen:1;
  unsigned state_rtmp_c2s_hand:1;
  unsigned state_rtmp_s2c_hand:1;

  /* Crypto (anonymization) identification */
  Bool crypto_src;
  Bool crypto_dst;
  
  char   *ssl_client_subject;
  char   *ssl_server_subject;
  enum npnalpn ssl_client_npnalpn;
  enum npnalpn ssl_server_npnalpn;
  timeval ssl_client_data_time;
  timeval ssl_server_data_time;
  timeval ssl_client_before_data_time;
  timeval ssl_server_before_data_time;
  seqnum  ssl_client_data_byte;
  seqnum  ssl_server_data_byte;
  Bool    ssl_client_data_seen;
  Bool    ssl_server_data_seen;
  Bool    ssl_sessionid_reuse;

  /* TLS 1.3 session related fields */
  char   *ssl_client_tls_version;
  char   *ssl_server_tls_version;
  Bool ssl_client_PSK;         /* Client Hello contained PSK extension */
  Bool ssl_server_PSK;         /* Server Hello contained PSK extension */
  Bool ssl_client_early_data;  /* Client Hello contained early_data extension */
  Bool ssl_server_hello_retry; /* Server answered with HelloRetry message */

  char *ssl_client_hello_buffer;
  int  ssl_client_hello_offset;
  int  ssl_client_hello_message_len;


  /* DNS reverse lookup */
  char* dns_name;
  ipaddr  dns_server;
  timeval request_time;
  timeval response_time;
  Bool    crypto_dns;  /* DNS Server matches the crypto requirements */
  
  /* Exclude packets from this flow when generating the tcp_complete.pcap */
   Bool stop_dumping_tcp;

  /* log periodic*/
  timeval last_print_time;
  tcb last_print_c2s;
  tcb last_print_s2c;

};
typedef struct stcp_pair tcp_pair;

typedef struct tcphdr tcphdr;

typedef struct ptp_snap
{
  tcp_pair_addrblock addr_pair;	/* just a copy */
  struct ptp_snap *next;
  tcp_pair *ptp;
  tcp_pair **ttp_ptr;
}
ptp_snap;

extern int num_tcp_pairs;	/* how many pairs are in use */
extern tcp_pair **ttp;		/* array of pointers to allocated pairs */

/* What UDP payload is in this flow.
   The values are reported in log_udp_complete, so they must not change */
enum udp_type
{ UDP_UNKNOWN    = 0,
  FIRST_RTP      = 1,
  FIRST_RTCP     = 2,
  RTP            = 3,
  RTCP           = 4,
  DNS            = 19,
  UDP_DTLS       = 26,
  UDP_QUIC       = 27,
  FIRST_RTP_PLUS = 28,
  RTP_PLUS       = 29,
  UDP_MTURN      = 30,
  LAST_UDP_PROTOCOL
};

typedef struct rtp rtp;
typedef struct rtcp rtcp;

#define MAX_COUNT_RTP_PT 10
#define MAX_COUNT_RTP_SSRC 1000

struct rtp
{

  u_int16_t packets_win[RTP_WIN];	/* the sliding window vector used to track
				   seqnum */
  Bool w;			/* true if we got a full window */
  u_int16_t initial_seqno;
  u_int16_t largest_seqno;
  u_long pnum;			/* number of segments */
  u_int32_t ssrc;
  timeval first_time;
  timeval last_time;
  long int n_out_of_sequence;
  double sum_delta_t;
  int n_delta_t;
  int transit;
  u_int32_t first_ts;
  u_int32_t largest_ts;
  double jitter;
  float jitter_max;
  float jitter_min;
  long int n_dup;
  long int n_late;
  long int n_lost;
  int burst;
  u_llong data_bytes;
  /* topix */
  unsigned char pt; /* Legacy - currently only used for the histograms */
  unsigned char pt_id[MAX_COUNT_RTP_PT];
  int pt_counter[MAX_COUNT_RTP_PT];
  int bogus_reset_during_flow; /* some Cisco implementation reset seqno ... */
  /* end topix */
  u_int32_t max_payload_bytes;
  u_int32_t min_payload_bytes;
  double squared_data_bytes;
  // Audio/Video reference values
  int av_transit[2];
  double av_jitter[2];
  float av_jitter_max[2];
  float av_jitter_min[2];
  
  rtp *next;
};


struct rtcp
{
  u_long pnum;			/* number of segments */
  u_int64_t initial_data_bytes;
  double sum_delta_t;		/* total interarrival time so far */
  timeval first_time;
  timeval last_time;
  u_int32_t ssrc;

  timeval last_SR;
  u_int32_t last_SR_id;
  u_int32_t tx_p;
  u_int32_t tx_b;

  double jitter_sum;
  double jitter_max;
  double jitter_min;
  u_int32_t jitter_samples;

  double rtt_sum;
  double rtt_max;
  double rtt_min;
  u_int32_t rtt_samples;

  int32_t c_lost;
  u_int8_t f_lost;
  double f_lost_sum;
  int rtcp_header_error;
  /* Track multiple PT per SSRC -MMM- */ 
  unsigned char pt_id[MAX_COUNT_RTP_PT];
  int pt_counter[MAX_COUNT_RTP_PT];
  u_int64_t rtcp_data_bytes; /* A different databytes counter */
  
  rtcp *next;
};


enum QUIC_udp_state
{
  QUIC_UNKNOWN=0,
  QUIC_OPENV_SENT,
  QUIC_OPEN_SENT,
  QUIC_DATA_SENT
};

/* minimal support for UDP "connections" */
typedef struct ucb
{
  /* parent pointer */
  struct sudp_pair *pup;

  timeval first_pkt_time;	/* time of the first pkt seen */
  timeval last_pkt_time;	/* time of the last pkt seen */
  enum udp_type type;
  enum QUIC_udp_state QUIC_state;
  char QUIC_conn_id[20];
  int QUIC_seq_nr;
  int QUIC_dir; /* 0 (client side) / 1 (server side) */
  Bool is_QUIC;

  struct
  {
    rtp *rtp_ptr;
    rtcp *rtcp_ptr;
  } flow_ptr;
  u_int16_t multiplexed_protocols; /* Bitmask for additional UDP protocols */
  
  /* statistics added */
  u_llong data_bytes;
  u_llong packets;
    /*TOPIX*/ u_int ttl_min;
  u_int ttl_max;
  u_llong ttl_tot;
  /*end TOPIX */

  /* Store information on the first MAX_COUNT_SEGMENTS segments */
#ifdef PACKET_STATS
  u_int seg_count;
  u_int seg_size[MAX_COUNT_SEGMENTS];
  double last_seg_time;
  double seg_intertime[MAX_COUNT_SEGMENTS];
  double data_pkts_sum2;
  double seg_intertime_sum;
  double seg_intertime_sum2;
#endif
}
ucb;


typedef tcp_pair_addrblock udp_pair_addrblock;

struct sudp_pair
{
  /* endpoint identification */
  udp_pair_addrblock addr_pair;

  /* connection naming information */
  Bool internal_src;
  Bool internal_dst;

  /* connection information */
  timeval first_time;
  timeval last_time;
  u_llong packets;
  ucb c2s;
  ucb s2c;

  /* Crypto identification */
  Bool crypto_src;
  Bool crypto_dst;

  /* linked list of usage */
  struct sudp_pair *next;

  /* DNS reverse lookup */
  char *dns_name;
  ipaddr  dns_server;
  timeval request_time;
  timeval response_time;
  Bool    crypto_dns;  /* DNS Server matches the crypto requirements */
  
  /* QUIC info */
  char *quic_sni_name;
  char *quic_ua_string;
  char quic_c_vers [4];
  char quic_s_vers [4];
  uint8_t quic_zero_rtt;
  uint8_t quic_ech;
  char *quic_client_hello;
  uint16_t quic_client_hello_len;

  /* Has STUN, for dump */
  Bool is_stun_initiated;

  /* log periodic*/
  timeval last_print_time;
  ucb last_print_c2s;
  ucb last_print_s2c;
  
};
typedef struct sudp_pair udp_pair;
typedef struct udphdr udphdr;

struct L4_bitrates
{
  unsigned long long in[4];
  unsigned long long out[4];
  unsigned long long loc[4];
};

struct L7_bitrates
{
  unsigned long long in[L7_FLOW_TOT];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long out[L7_FLOW_TOT]; /* unsigned long long out[L7_FLOW_TOT] */
  unsigned long long loc[L7_FLOW_TOT]; /* unsigned long long loc[L7_FLOW_TOT] */
};

struct L3_bitrates
{
  unsigned long long in[L3_LAST_TYPE];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long out[L3_LAST_TYPE]; /* unsigned long long out[L7_FLOW_TOT] */
  unsigned long long loc[L3_LAST_TYPE]; /* unsigned long long loc[L7_FLOW_TOT] */
};

/*-----------------------------------------------------------*/
/* RRDtools 				                     */

struct rrdconf
{
  Bool rrd;			/* boolean: whether to use rrd on this histo */
  Bool avg, min, max, var, stdev, idxoth, hit;	/* statistical var to dump */
  int *idx;			/* indexes to dump */
  int idxno;
  double *prc;			/* percentiles to dump */
  int prcno;
};

struct rrdstat
{
  double avg, min, max, pseudovar;	/* actual values of the statistical var to dump */
  long count;
  timeval last;
};
/*-----------------------------------------------------------*/


enum ip_direction {
 DEFAULT_NET     = 0,
 SRC_IN_DST_IN   = 1,
 SRC_IN_DST_OUT  = 2,
 SRC_OUT_DST_IN  = 3,
 SRC_OUT_DST_OUT = 4
};

/* Struct mirroring the constants defined in param.h */

struct global_parameters {

 int Max_Internal_Ethers;
 int Max_Internal_Hosts;
 int Max_Crypto_Hosts;
 int Max_White_Hosts;

 int Max_Seg_Per_Quad;
 
 int TCP_Idle_Time;
 int UDP_Idle_Time;
 int TCP_Singleton_Time;
 int UDP_Singleton_Time;
 
 int GC_Cycle_Time;
 int GC_Split_Ratio;
 int GC_Fire_Time; /* We keep it global, but as a derived value */

 double Runtime_Config_Idle;
 int Runtime_Mtime_Counter;

 int Max_TCP_Pairs;
 int Max_UDP_Pairs;
 
 int List_Search_Dept;
 
 int Hash_Table_Size;

 double Max_Time_Step;
 
 int Dirs;

 double Min_Delta_T_UDP_Dup_Pkt;
 double Min_Delta_T_TCP_Dup_Pkt;

 int Log_Periodic_Interval;

 int Max_Crypto_Cache_Size;

 int DNS_Cache_Size;
 int DNS_Cache_Size_IPv6;
 
 int Crypto_IPv6_Mask_0;
 int Crypto_IPv6_Mask_1;
 int Crypto_IPv6_Mask_2;
 int Crypto_IPv6_Mask_3;
 
};

typedef struct param_value
{
  enum   { INTEGER, DOUBLE, STRING } type;
  union  {
  int    ivalue;
  double dvalue;
  char   *svalue;
  } value;
} param_value;
