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

#ifndef _HISTO_H_
#define _HISTO_H_
#define RRD_NAME_MAXLEN    19
#define HISTO_NAME_MAXLEN  (RRD_NAME_MAXLEN+20)
#define HISTO_DESCR_MAXLEN 256


/****************aste************/
struct double_histo_list
{
  char name[HISTO_NAME_MAXLEN];
  char descr[HISTO_DESCR_MAXLEN];

#define HISTO_OFF 0 
#define HISTO_ON  1
#define HISTO_RRD 2
  int flag; 
  
  
/*-----------------------------------------------------------*/
/* RRDtools 				                     */
  struct rrdstat st;
  struct rrdconf conf;
/*-----------------------------------------------------------*/
  long min;
  long max;
  long bin_size;

  long bin_num;  // ((max - min) / bin_size) + 3 

#define BIN_LESS_MIN(histo)	 (0)
/* data[0]: counts samples smaller than min  */

#define BIN_BETWEEN(histo, val)  (((int) val + histo->bin_size - histo->min) / (int) histo->bin_size)
/* data[1 ... bin_num-3]:  counts samples between min and max with a step equal to delta */

#define BIN_MORE_MAX(histo)      (histo->bin_num-2)
/* data[num_col-1]: counts samples larger than max */

#define BIN_SAMPLE_COUNT(histo)  (histo->bin_num-1)
/* data[num_col]:  count *all* samples (used to speed up RRD percentile estimation) */


  long *first_data;
  long *second_data;
  long *current_data;
  struct double_histo_list *next;
};
/*********************************/


/* Limits for SHORT */
#define SHORT_MM_CL_B 100000	/*[bytes] */
#define SHORT_MM_CL_P 1000	/*[packets] */
#define SHORT_MM_TOT_TIME 5000	/*[ms] */
#define BITRATE_MIN_PKTS 5


/* prototypes of functions */

struct double_histo_list *find_histo(char *hname);
void alloc_histo (struct double_histo_list *thisto);

struct double_histo_list *first_histo_list ();
void create_all_histo (void);
struct double_histo_list *create_histo (char *name, char *descr, long min,
					long max, long bin_size);

#define add_histo(hp, v)  {if(hp->flag == HISTO_ON){ __add_histo (hp, v);}}
void set_histo (struct double_histo_list *p, int index, double val);
void __add_histo (struct double_histo_list *p, double val);
void update_fake_histos();
void swap_histo ();
long *whats_frozen (struct double_histo_list *histo);

int clear_all_histo ();
int clear_histo (struct double_histo_list *phisto);

void flush_histo ();



/* topix bitrate */

void fake_histo_bitrate_update (struct double_histo_list *phisto,
				double elapsed_time,
				unsigned long long *, int );

/*-------------------------------------------------------------*/
/* here are all the histo tracked by tstat                     */
/* struct double_histo_list *test;                             */
/* NOTE                                                         */
/*      variable name MUST be SHORTER (<) than 20               */
/*      char, otherwise RRD will complain without               */
/*      further explaining the error                            */
/*-------------------------------------------------------------*/


extern struct double_histo_list *ip_bitrate_in;
extern struct double_histo_list *ip_bitrate_out;
extern struct double_histo_list *ip_bitrate_loc;


extern struct double_histo_list *ip_protocol_in;
extern struct double_histo_list *ip_protocol_out;
extern struct double_histo_list *ip_protocol_loc;

extern struct double_histo_list *ip_len_out;
extern struct double_histo_list *ip_len_in;
extern struct double_histo_list *ip_len_loc;

extern struct double_histo_list *ip_ttl_out;
extern struct double_histo_list *ip_ttl_in;
extern struct double_histo_list *ip_ttl_loc;

extern struct double_histo_list *ip_tos_out;
extern struct double_histo_list *ip_tos_in;
extern struct double_histo_list *ip_tos_loc;

//IPv6 module

extern struct double_histo_list *ip6_protocol_in;
extern struct double_histo_list *ip6_hop_limit_in;
extern struct double_histo_list *ip6_plen_in;

extern struct double_histo_list *ip6_protocol_out;
extern struct double_histo_list *ip6_hop_limit_out;
extern struct double_histo_list *ip6_plen_out;

extern struct double_histo_list *ip6_protocol_loc;
extern struct double_histo_list *ip6_hop_limit_loc;
extern struct double_histo_list *ip6_plen_loc;

//ICMPv6 module
extern struct double_histo_list *icmpv6_type_in;
extern struct double_histo_list *icmpv6_type_loc;
extern struct double_histo_list *icmpv6_type_out;
//IPv6 module


extern struct double_histo_list *tcp_port_src_in;
extern struct double_histo_list *tcp_port_src_out;
extern struct double_histo_list *tcp_port_src_loc;
extern struct double_histo_list *tcp_port_dst_in;
extern struct double_histo_list *tcp_port_dst_out;
extern struct double_histo_list *tcp_port_dst_loc;

extern struct double_histo_list *tcp_port_synsrc_in;
extern struct double_histo_list *tcp_port_synsrc_out;
extern struct double_histo_list *tcp_port_synsrc_loc;
extern struct double_histo_list *tcp_port_syndst_in;
extern struct double_histo_list *tcp_port_syndst_out;
extern struct double_histo_list *tcp_port_syndst_loc;

extern struct double_histo_list *tcp_bitrate_in;
extern struct double_histo_list *tcp_bitrate_out;
extern struct double_histo_list *tcp_bitrate_loc;

extern struct double_histo_list *tcp_opts_SACK;
extern struct double_histo_list *tcp_opts_WS;
extern struct double_histo_list *tcp_opts_TS;
extern struct double_histo_list *tcp_opts_MPTCP;

extern struct double_histo_list *tcp_mss_a;
extern struct double_histo_list *tcp_mss_b;
extern struct double_histo_list *tcp_mss_used;

extern struct double_histo_list *tcp_win_min;
extern struct double_histo_list *tcp_win_avg;
extern struct double_histo_list *tcp_win_max;

extern struct double_histo_list *tcp_cwnd;

extern struct double_histo_list *tcp_cl_b_l_out;
extern struct double_histo_list *tcp_cl_b_l_in;
extern struct double_histo_list *tcp_cl_b_l_loc;
extern struct double_histo_list *tcp_cl_b_s_out;
extern struct double_histo_list *tcp_cl_b_s_in;
extern struct double_histo_list *tcp_cl_b_s_loc;
extern struct double_histo_list *tcp_cl_p_out;
extern struct double_histo_list *tcp_cl_p_in;
extern struct double_histo_list *tcp_cl_p_loc;

extern struct double_histo_list *tcp_cl_b_l_c2s;
extern struct double_histo_list *tcp_cl_b_l_s2c;
extern struct double_histo_list *tcp_cl_b_s_c2s;
extern struct double_histo_list *tcp_cl_b_s_s2c;
extern struct double_histo_list *tcp_cl_p_c2s;
extern struct double_histo_list *tcp_cl_p_s2c;

extern struct double_histo_list *tcp_rtt_min_out;
extern struct double_histo_list *tcp_rtt_min_in;
extern struct double_histo_list *tcp_rtt_min_loc;
extern struct double_histo_list *tcp_rtt_min_c2s;
extern struct double_histo_list *tcp_rtt_min_s2c;

/* v.1.2.0 -----------------------------------*/

extern struct double_histo_list *tcp_rtt_avg_out;
extern struct double_histo_list *tcp_rtt_avg_in;
extern struct double_histo_list *tcp_rtt_avg_loc;
extern struct double_histo_list *tcp_rtt_avg_c2s;
extern struct double_histo_list *tcp_rtt_avg_s2c;


/* v.1.2.0 -----------------------------------*/

extern struct double_histo_list *tcp_rtt_max_out;
extern struct double_histo_list *tcp_rtt_max_in;
extern struct double_histo_list *tcp_rtt_max_loc;
extern struct double_histo_list *tcp_rtt_max_c2s;
extern struct double_histo_list *tcp_rtt_max_s2c;

extern struct double_histo_list *tcp_rtt_stdev_out;
extern struct double_histo_list *tcp_rtt_stdev_in;
extern struct double_histo_list *tcp_rtt_stdev_loc;
extern struct double_histo_list *tcp_rtt_stdev_c2s;
extern struct double_histo_list *tcp_rtt_stdev_s2c;

extern struct double_histo_list *tcp_rtt_cnt_out;
extern struct double_histo_list *tcp_rtt_cnt_in;
extern struct double_histo_list *tcp_rtt_cnt_loc;
extern struct double_histo_list *tcp_rtt_cnt_c2s;
extern struct double_histo_list *tcp_rtt_cnt_s2c;

extern struct double_histo_list *tcp_anomalies_c2s;
extern struct double_histo_list *tcp_anomalies_s2c;
extern struct double_histo_list *tcp_anomalies_out;
extern struct double_histo_list *tcp_anomalies_in;
extern struct double_histo_list *tcp_anomalies_loc;

extern struct double_histo_list *tcp_rtx_RTO_c2s;
extern struct double_histo_list *tcp_rtx_RTO_s2c;
extern struct double_histo_list *tcp_rtx_RTO_out;
extern struct double_histo_list *tcp_rtx_RTO_in;
extern struct double_histo_list *tcp_rtx_RTO_loc;

extern struct double_histo_list *tcp_rtx_FR_c2s;
extern struct double_histo_list *tcp_rtx_FR_s2c;
extern struct double_histo_list *tcp_rtx_FR_out;
extern struct double_histo_list *tcp_rtx_FR_in;
extern struct double_histo_list *tcp_rtx_FR_loc;

extern struct double_histo_list *tcp_reordering_c2s;
extern struct double_histo_list *tcp_reordering_s2c;
extern struct double_histo_list *tcp_reordering_out;
extern struct double_histo_list *tcp_reordering_in;
extern struct double_histo_list *tcp_reordering_loc;

extern struct double_histo_list *tcp_net_dup_c2s;
extern struct double_histo_list *tcp_net_dup_s2c;
extern struct double_histo_list *tcp_net_dup_out;
extern struct double_histo_list *tcp_net_dup_in;
extern struct double_histo_list *tcp_net_dup_loc;

extern struct double_histo_list *tcp_unknown_c2s;
extern struct double_histo_list *tcp_unknown_s2c;
extern struct double_histo_list *tcp_unknown_out;
extern struct double_histo_list *tcp_unknown_in;
extern struct double_histo_list *tcp_unknown_loc;

extern struct double_histo_list *tcp_flow_ctrl_c2s;
extern struct double_histo_list *tcp_flow_ctrl_s2c;
extern struct double_histo_list *tcp_flow_ctrl_out;
extern struct double_histo_list *tcp_flow_ctrl_in;
extern struct double_histo_list *tcp_flow_ctrl_loc;

extern struct double_histo_list *tcp_unnrtx_RTO_c2s;
extern struct double_histo_list *tcp_unnrtx_RTO_s2c;
extern struct double_histo_list *tcp_unnrtx_RTO_out;
extern struct double_histo_list *tcp_unnrtx_RTO_in;
extern struct double_histo_list *tcp_unnrtx_RTO_loc;

extern struct double_histo_list *tcp_unnrtx_FR_c2s;
extern struct double_histo_list *tcp_unnrtx_FR_s2c;
extern struct double_histo_list *tcp_unnrtx_FR_out;
extern struct double_histo_list *tcp_unnrtx_FR_in;
extern struct double_histo_list *tcp_unnrtx_FR_loc;


extern struct double_histo_list *tcp_tot_time;
extern struct double_histo_list *tcp_thru_c2s;
extern struct double_histo_list *tcp_thru_s2c;

extern struct double_histo_list *tcp_thru_lf_c2s;
extern struct double_histo_list *tcp_thru_lf_s2c;

extern struct double_histo_list *tcp_interrupted;

extern struct double_histo_list *L4_flow_number;


    /* udp histograms */

extern struct double_histo_list *udp_cl_p_out;
extern struct double_histo_list *udp_cl_p_in;
extern struct double_histo_list *udp_cl_p_loc;

extern struct double_histo_list *udp_cl_b_l_out;
extern struct double_histo_list *udp_cl_b_l_in;
extern struct double_histo_list *udp_cl_b_l_loc;
extern struct double_histo_list *udp_cl_b_s_out;
extern struct double_histo_list *udp_cl_b_s_in;
extern struct double_histo_list *udp_cl_b_s_loc;

extern struct double_histo_list *udp_tot_time;
extern struct double_histo_list *udp_port_dst_in;
extern struct double_histo_list *udp_port_dst_out;
extern struct double_histo_list *udp_port_dst_loc;
extern struct double_histo_list *udp_port_flow_dst;

extern struct double_histo_list *udp_bitrate_in;
extern struct double_histo_list *udp_bitrate_out;
extern struct double_histo_list *udp_bitrate_loc;

      /* stream histograms */

extern struct double_histo_list *mm_type_in;
extern struct double_histo_list *mm_type_out;
extern struct double_histo_list *mm_type_loc;

extern struct double_histo_list *mm_rtp_pt_in;
extern struct double_histo_list *mm_rtp_pt_out;
extern struct double_histo_list *mm_rtp_pt_loc;

extern struct double_histo_list *mm_uni_multi_in;
extern struct double_histo_list *mm_uni_multi_out;
extern struct double_histo_list *mm_uni_multi_loc;

extern struct double_histo_list *mm_tot_time_in;
extern struct double_histo_list *mm_tot_time_out;
extern struct double_histo_list *mm_tot_time_loc;

extern struct double_histo_list *mm_tot_time_s_in;
extern struct double_histo_list *mm_tot_time_s_out;
extern struct double_histo_list *mm_tot_time_s_loc;


extern struct double_histo_list *mm_cl_p_out;
extern struct double_histo_list *mm_cl_p_in;
extern struct double_histo_list *mm_cl_p_loc;

extern struct double_histo_list *mm_cl_b_out;
extern struct double_histo_list *mm_cl_b_in;
extern struct double_histo_list *mm_cl_b_loc;

extern struct double_histo_list *mm_cl_p_s_out;
extern struct double_histo_list *mm_cl_p_s_in;
extern struct double_histo_list *mm_cl_p_s_loc;

extern struct double_histo_list *mm_cl_b_s_out;
extern struct double_histo_list *mm_cl_b_s_in;
extern struct double_histo_list *mm_cl_b_s_loc;

extern struct double_histo_list *mm_avg_bitrate_in;
extern struct double_histo_list *mm_avg_bitrate_out;
extern struct double_histo_list *mm_avg_bitrate_loc;

extern struct double_histo_list *mm_avg_ipg_in;
extern struct double_histo_list *mm_avg_ipg_out;
extern struct double_histo_list *mm_avg_ipg_loc;

extern struct double_histo_list *mm_avg_jitter_in;
extern struct double_histo_list *mm_avg_jitter_out;
extern struct double_histo_list *mm_avg_jitter_loc;

extern struct double_histo_list *mm_n_oos_in;
extern struct double_histo_list *mm_n_oos_out;
extern struct double_histo_list *mm_n_oos_loc;
extern struct double_histo_list *mm_p_oos_in;
extern struct double_histo_list *mm_p_oos_out;
extern struct double_histo_list *mm_p_oos_loc;
extern struct double_histo_list *mm_p_dup_in;
extern struct double_histo_list *mm_p_dup_out;
extern struct double_histo_list *mm_p_dup_loc;
extern struct double_histo_list *mm_p_lost_in;
extern struct double_histo_list *mm_p_lost_out;
extern struct double_histo_list *mm_p_lost_loc;
extern struct double_histo_list *mm_p_late_in;
extern struct double_histo_list *mm_p_late_out;
extern struct double_histo_list *mm_p_late_loc;
extern struct double_histo_list *mm_burst_loss_in;
extern struct double_histo_list *mm_burst_loss_out;
extern struct double_histo_list *mm_burst_loss_loc;
extern struct double_histo_list *mm_reord_p_n_in;
extern struct double_histo_list *mm_reord_p_n_out;
extern struct double_histo_list *mm_reord_p_n_loc;
extern struct double_histo_list *mm_reord_delay_in;
extern struct double_histo_list *mm_reord_delay_out;
extern struct double_histo_list *mm_reord_delay_loc;
extern struct double_histo_list *mm_oos_p_in;
extern struct double_histo_list *mm_oos_p_out;
extern struct double_histo_list *mm_oos_p_loc;

      /* rtcp histograms */

extern struct double_histo_list *rtcp_cl_p_out;
extern struct double_histo_list *rtcp_cl_p_in;
extern struct double_histo_list *rtcp_cl_p_loc;
extern struct double_histo_list *rtcp_cl_b_out;
extern struct double_histo_list *rtcp_cl_b_in;
extern struct double_histo_list *rtcp_cl_b_loc;
extern struct double_histo_list *rtcp_avg_inter_in;
extern struct double_histo_list *rtcp_avg_inter_out;
extern struct double_histo_list *rtcp_avg_inter_loc;
extern struct double_histo_list *rtcp_bt_in;
extern struct double_histo_list *rtcp_bt_out;
extern struct double_histo_list *rtcp_bt_loc;
extern struct double_histo_list *rtcp_mm_bt_in;
extern struct double_histo_list *rtcp_mm_bt_out;
extern struct double_histo_list *rtcp_mm_bt_loc;
extern struct double_histo_list *rtcp_lost_in;
extern struct double_histo_list *rtcp_lost_out;
extern struct double_histo_list *rtcp_lost_loc;
extern struct double_histo_list *rtcp_dup_in;
extern struct double_histo_list *rtcp_dup_out;
extern struct double_histo_list *rtcp_dup_loc;
extern struct double_histo_list *rtcp_f_lost_in;
extern struct double_histo_list *rtcp_f_lost_out;
extern struct double_histo_list *rtcp_f_lost_loc;
extern struct double_histo_list *rtcp_t_lost_in;
extern struct double_histo_list *rtcp_t_lost_out;
extern struct double_histo_list *rtcp_t_lost_loc;
extern struct double_histo_list *rtcp_mm_cl_p_in;
extern struct double_histo_list *rtcp_mm_cl_p_out;
extern struct double_histo_list *rtcp_mm_cl_p_loc;
extern struct double_histo_list *rtcp_mm_cl_b_in;
extern struct double_histo_list *rtcp_mm_cl_b_out;
extern struct double_histo_list *rtcp_mm_cl_b_loc;
extern struct double_histo_list *rtcp_jitter_in;
extern struct double_histo_list *rtcp_jitter_out;
extern struct double_histo_list *rtcp_jitter_loc;
extern struct double_histo_list *rtcp_rtt_in;
extern struct double_histo_list *rtcp_rtt_out;
extern struct double_histo_list *rtcp_rtt_loc;

/* global bitrate */

/* Application stat */

extern struct double_histo_list *L7_TCP_num_out;
extern struct double_histo_list *L7_TCP_num_in;
extern struct double_histo_list *L7_TCP_num_loc;

extern struct double_histo_list *L7_UDP_num_out;
extern struct double_histo_list *L7_UDP_num_in;
extern struct double_histo_list *L7_UDP_num_loc;


/* IPv4/IPv6 statistics */
extern struct double_histo_list *L3_protocol_out;
extern struct double_histo_list *L3_protocol_in;
extern struct double_histo_list *L3_protocol_loc;
extern struct double_histo_list *L3_bitrate_out;
extern struct double_histo_list *L3_bitrate_in;
extern struct double_histo_list *L3_bitrate_loc;


#endif
