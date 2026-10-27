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

static char const copyright[] =
  "@(#)Copyright (c) 2001-2018 -- Telecomunication Network Group \
     -- Politecnico di Torino.  All rights reserved.\
     Tstat is based on TCPTRACE,\
    @(#)Copyright (c) 1999 -- Shawn Ostermann -- Ohio University.\n";

#include "tstat.h"
#include "version.h"
#include <sys/wait.h>
#include <getopt.h>
#include <fcntl.h>
#include "globals.h"
#include "options.h"

/* version information */
char *tstat_version = VERSION;

/* Global struct with the content of param.h*/
struct global_parameters GLOBALS;

/* local routines */
void QuitSig (int);
void Usr1Sig (int);
static void Formats (void);
static void Help ();
static void CheckArguments (int *pargc, char *argv[]);
static void ParseArgs (int *pargc, char *argv[]);
static void Usage (void);
static void BadArg (char *argsource, char *format, ...);
static void Version (void);
static int LoadInternalNets (char *file);
static int LoadCryptoNets (char *file);
static int LoadWhiteNets (char *file);
#ifndef TSTAT_RUNASLIB
static void ProcessFile (char *filename, Bool last);
#endif

Bool internal_eth (uint8_t *eth_addr, eth_filter *filter);
int LoadInternalEth (char *file);


static int ip_header_stat (int phystype, struct ip *pip, u_long * fpnum,
			   u_long * pcount, int file_count, char *filename,
			   long int location, int tlen, void *plast,
			   int ip_direction);

static void flush_time_step(void);

Bool filter_specified = FALSE;
char *filter_filename;
char *dev;

static Bool basedirspecified = FALSE;
static char *basenamedir;
static char basename[FILENAME_SIZE];
Bool internal_src = FALSE;
Bool internal_dst = FALSE;

struct in_addr *internal_net_list;
struct in6_addr *internal_net_listv6;
int *internal_net_mask;
int *internal_net_maskv6;
int tot_internal_nets;
int tot_internal_netsv6;

/* Variables for Crypto definition*/
Bool crypto_src = FALSE;
Bool crypto_dst = FALSE;

struct in_addr *crypto_net_list;
struct in6_addr *crypto_net_listv6;
int *crypto_net_mask;
int *crypto_net_maskv6;
int tot_crypto_nets;
int tot_crypto_netsv6;

struct in_addr *white_net_list;
struct in6_addr *white_net_listv6;
int *white_net_mask;
int *white_net_maskv6;
int tot_white_nets;
int tot_white_netsv6;

unsigned int ip_obfuscate_mask = 0x00000000; /* This is already in network order */

/* option flags and default values */
Bool live_flag = FALSE;

Bool printticks = FALSE;

Bool warn_IN_OUT = TRUE;
Bool warn_ooo = FALSE;
Bool warn_MAX_ = TRUE;
Bool warn_printtrunc = FALSE;
Bool warn_printbadmbz = FALSE;
Bool warn_printbadcsum = FALSE;
Bool warn_printbad_syn_fin_seq = FALSE;
Bool do_udp = TRUE;
int debug = 0;
char **filenames = NULL;

Bool con_cat = FALSE;		/* Concatenate the input files */
Bool first_ip_packet = TRUE;
u_long pnum = 0;
u_long ctrunc = 0;
u_long bad_ip_checksums = 0;
u_long bad_tcp_checksums = 0;
u_long bad_udp_checksums = 0;

/* globals */
struct timeval current_time;

unsigned long int fcount = 0;	/* total flow number */
unsigned long int f_TCP_count = 0;	/* total TCP  flow number */
unsigned long int f_UDP_count = 0;	/* total UDP flow number */
unsigned long int f_RTP_count = 0;	/* total RTP flow number */
unsigned long int f_RTCP_count = 0;	/* total RTP flow number */
unsigned long int f_RTP_tunneled_TCP_count = 0;	/* total RTP flow tunneled on TCP */

unsigned long tot_conn_TCP = 0;
unsigned long tot_conn_UDP = 0;

struct L3_bitrates L3_bitrate;
struct L4_bitrates L4_bitrate;
struct L7_bitrates L7_bitrate;
struct L7_bitrates L7_udp_bitrate;

static u_long pcount = 0;   //global packet counter
static u_long fpnum = 0;    //per file packet counter
static int file_count = 0;

/*-----------------------------------------------------------*/
/* RRDtools 				                     */
/*-----------------------------------------------------------*/
Bool rrdset_path = FALSE;	/* database path flag */
Bool rrdset_conf = FALSE;	/* configuration file flag */
/*-----------------------------------------------------------*/

Bool runtime_engine = FALSE;    /* -T */
Bool rrd_engine = FALSE;

Bool strict_privacy = FALSE;   /* -0 */

Bool report_dnscache = FALSE;

int log_level = TCP_LOG_ALL;
Bool force_create_new_outfiles = FALSE;

/* locally global variables */
static u_long filesize = 0;
static int num_files = 0;
#ifndef TSTAT_RUNASLIB
static u_int numfiles;
#endif
static char *cur_filename;
static unsigned int step = 0;	/* number of time steps since the creation
				   of the current output directory */
static Bool first_packet_readed = FALSE; 

static time_t last_mtime;           //last time runtime config file is changed
static time_t last_mtime_check;
static int mtime_stable_counter;    //when this counter is 0, read again runtime config    

int snaplen = DEFAULT_SNAPLEN;    /* Snaplen for the live capture */

/* for elapsed processing time */
struct timeval wallclock_start;
struct timeval wallclock_finished;
struct timeval wallclock_temp;

/* first and last packet timestamp */
timeval first_packet = { 0, 0 };
timeval last_packet = { 0, 0 };

/* .a.c. */
Bool is_stdin;
FILE *fp_stdout = NULL;
FILE *fp_stderr = NULL;
FILE *fp_logc = NULL;
FILE *fp_lognc = NULL;
FILE *fp_rtp_logc = NULL;
FILE *fp_udp_logc = NULL;
FILE *fp_periodic_logc = NULL;
FILE *fp_periodic_udp_logc = NULL;

FILE *fp_http_logc = NULL;

FILE *fp_dns_logc = NULL;

long log_bitmask = LOG_ALL;

/* discriminate Direction */
/* used when checking by Ethernet MAC */
eth_filter mac_filter;
Bool internal_dhost;
Bool internal_shost;
/* used when relying on IP addresses */
Bool net_conf = FALSE;
Bool crypto_conf = FALSE;
Bool white_conf = FALSE;
Bool eth_conf = FALSE;

int  crypto_source = CPKEY_UNDEF;
char *crypto_value = NULL;
int  key_modes_set = 0;
Bool enc_string_set = FALSE;

int  globals_set = 0;

long int tcp_packet_count;
extern long not_id_p;
extern int search_count;

extern char dump_conf_fname[];
char runtime_conf_fname[200];
//static timeval last_runtime_check = {-1,-1};
timeval last_time_step;
timeval last_cleaned;


char *dns_namefilter_file;
Bool dns_namefilter_specified = FALSE;
Bool dns_enabled = TRUE;

Bool ipv6_enabled = TRUE;


static void
Help (void)
{
  fprintf (fp_stderr,
    "Usage:\n"
    "\ttstat [-htucvwLQX0] [-d[-d]]\n"
    "\t      [-s dir]\n"
    "\t      [-N file]\n"
    "\t      [-M file]\n"
    "\t      [-Y file]\n"
    "\t      [--keyvalue key | --keyfile file | --keybase64 file]\n"
    "\t      [--enc]\n"
    "\t      [-W file]\n"
    "\t      [-T runtime.conf]\n"
    "\t      [-G globals.conf]\n"
    "\t      [-z file]\n"
    "\t      [-A mask]\n"
    "\t      [-6]\n"
    "\t      [-F file]\n"
    "\t      [-r RRD_out_dir] [-R rrd_conf]\n"
    "\t      [-l] [-i interface] [-E snaplen]\n"
    "\t      [-f filterfile]\n"
    "\t      <file1 file2>\n"
    "\n"
    "Options:\n"
    "\t-h: print this help and exit\n"
    "\t-t: print ticks showing the trace analysis progress\n"
    "\t-u: do not trace UDP packets\n"
    "\t-v: print version and exit\n"
    "\t-w: print [lots] of warning\n"
    "\t-c: concatenate the input files\n"
    "\t    (input files should already be in the correct order)\n"
    "\t-0: force the strict(er) privacy mode for logs\n"
    "\t-d: increase debug level (repeat to increase debug level)\n"
    "\n"
    "\t-s dir: puts the trace analysis results into directory\n"
    "\t        tree dir (otherwise will be <file>.out)\n"
    "\t-N file: specify the file name which contains the\n"
    "\t         description of the internal networks.\n"
    "\t         This file must contain the subnets that will be\n"
    "\t         considered as 'internal' during the analysis.\n"
    "\t         Each subnet can be specified in one of the following types:\n"
    "\t         - <Network IPv4/MaskLen> on a single line \n"
    "\t             130.192.0.0/16\n"
    "\t         - <Network IPv6/MaskLen> on a single line \n"
    "\t             2001:db8::/32\n"
    "\t         - <Network IPv4/NetMask IPv4> on a single line \n"
    "\t             130.192.0.0/255.255.0.0\n"
    "\t         - Pairs of lines with <Network IPv4> and <NetMask IPv4>\n"
    "\t             130.192.0.0\n"
    "\t             255.255.0.0\n"
    "\t         If the option is not specified all networks are\n"
    "\t         considered internal\n"
    "\n"
    "\t-M file: specify the file name which contains the\n"
    "\t         description of the MAC addesses that are to be considered internal.\n"
    "\t         MAC addresses must be in the 6 digit - hex notation.\n"
    "\t         Example:\n"
    "\t                11:22:33:44:55:66 \n"
    "\t                66:55:44:33:22:11 \n"
    "\t         If this option is specified, the -N param is ignored.\n"
    "\n"
    "\t-Y file: specify the file name which contains the\n"
    "\t         description of the encrypted IPv4 networks.\n"
    "\t         This file must contain the subnets for which the IPv4 address\n"
    "\t         will be anonymized using the Crypto-PAn algorithm.\n"
    "\t         Subnets are specified like in the -N option.\n"
    "\n"
    "\t--keyvalue key: specify a string to be used as the key for address\n"
    "\t         anonymization.\n"
    "\t         Valid only if the -Y option is also specified. Only one option\n"
    "\t         among --keyvalue, --keyfile, and --keybase64 can be used.\n"
    "\n"
    "\t--keyfile file: specify the file name which contain the plain text key\n"
    "\t         for address anonymization.\n"
    "\t         Valid only if the -Y option is also specified. Only one option\n"
    "\t         among --keyvalue, --keyfile, and --keybase64 can be used.\n"
    "\n"
    "\t--keybase64 file: specify the file name which contain the Base64 encoded\n"
    "\t         key for address anonymization.\n"
    "\t         Valid only if the -Y option is also specified. Only one option\n"
    "\t         among --keyvalue, --keyfile, and --keybase64 can be used.\n"
    "\n"
    "\t--enc:   all hostnames in the log files are encrypted using the current key\n"
    "\t         and Base64 encoded.\n"
    "\t         Valid only if the -Y option is also specified.\n"
    "\n"
    "\t-W file: specify the file name which contains the\n"
    "\t         description of the whitelisted IPv4 hosts/networks.\n"
    "\t         This file must contain the subnets for which the IPv4 address\n"
    "\t         will be whitelisted and *NOT* anonymized using the Crypto-PAn algorithm.\n"
    "\t         Subnets are specified like in the -N option.\n"
    "\t         Meaningful only if the -Y option is also specified.\n"
    "\n"
    "\t-L: No log engine: do not create log_* files \n"
    "\t-T runtime.conf: configuration file to enable/disable dumping\n"
    "\t                 of traces and logs at runtime\n" 
    "\t-G globals.conf: configuration file to provide at startup new values\n"
    "\t                 to the internal global configuration constants\n" 
    "\t-z file: redirect all the stdout/stderr messages to the file specified\n"
    "\t-A mask: enable XOR-based anonymization for internal IPv4 addresses.\n"
    "\t         'mask' is a decimal, octal, or hexadecimal value.\n"
    "\t-6: disable the L4 processing of IPv6 datagrams\n"
    "\t-X: disable the DN-Hunter DNS engine\n"
    "\t-Q: enable report of wrap-around events in the DN-Hunter caches\n"
    "\t-F file: specify the file name which contains the\n"
    "\t         list of DNS domains to be included/excluded from the\n"
    "\t         TCP traffic dump. Activated in the runtime configuration (-T)\n"
/*----------------------------------------------------------- 
   RRDtools 				                     
   these flags test for both the -r and -R options to be 
   specified when using RR database integration */
    "\t-R conf: specify the configuration file for integration with\n"
    "\t         RRDtool (see tstat-conf/rrd.conf)\n"
    "\t-r path: path to use to create/update the RRDtool database\n"
/*-----------------------------------------------------------*/
    "\t-l: enable live capture using libpcap\n"
    "\t-i interface: specifies the interface to be used to capture traffic\n"
    "\t-E snaplen: specifies the snaplen size used to capture traffic.\n"
    "\t            It might be overridden by the interface slen size\n"
    "\t-f filterfile: specifies the libpcap filter file. Syntax as in tcpdump\n"
    "\n"
    "\tfile: trace file to be analyzed\n"
    "\t      Use 'stdin' to read from standard input.\n"
    "\n"
    "Note:\n"
	"\tWhen tstat is called with no arguments (on the command line),\n"
	"\tit will first check if a file <tstat.conf> is provided in the\n"
    "\tsame directory where the execution started.\n"
	"\tIn the latter case, arguments will be read from <tstat.conf>\n"
    "\trather than from the command line\n"
    "\n");
  Formats ();
  PrintGlobals();
  Version ();
}


static void
BadArg (char *argsource, char *format, ...)
{
  va_list ap;

  Help ();

  fprintf (fp_stderr, "\nArgument error");
  if (argsource)
    fprintf (fp_stderr, " (from %s)", argsource);
  fprintf (fp_stderr, ": ");

  va_start (ap, format);
  vfprintf (fp_stderr, format, ap);
  va_end (ap);
  fprintf (fp_stderr, "\n");
  exit (EXIT_FAILURE);

}


static void
Usage (void)
{
  Help ();
  exit (0);
}


static void
Version (void)
{
  fprintf (fp_stderr, "\nVersion: %s\n", tstat_version);
  fprintf (fp_stderr, "Compiled by <%s>, on <%s> on machine <%s>",
	   built_bywhom, built_when, built_where);
  fprintf (fp_stderr, ANSI_BOLD " with " ANSI_RESET);
  fprintf (fp_stderr, "IPv6 support");
  fprintf (fp_stderr, " and");
  fprintf (fp_stderr, ANSI_BOLD " with " ANSI_RESET);
  fprintf (fp_stderr, "LDNS (log_dns) support");
  fprintf (fp_stderr, "\n\n");
}


static void
Formats (void)
{
  fprintf (fp_stderr, "Supported Input File Formats:\n");
  fprintf (fp_stderr, "\t%-15s  %s\n", "tcpdump",
	   "pcap and pcapng files, read through libpcap");
  fprintf (fp_stderr, "\t%-15s  %s\n", "tcpdump live",
	   "Live capture using libpcap");
}

#ifdef TSTAT_RUNASLIB
int tstat_init(char *config_fname) {
    int argc = 1;
    char *argv[1];
    argv[0] = (config_fname == NULL) ? "tstat.conf" : config_fname;
#else
/* add a fake function */
int tstat_init(char *config_fname) {
    return 0;
}

int
main (int argc, char *argv[]) {
  int i;
  double etime;
#endif

  /* initialize globals */
  InitGlobals();
  
  /* parse the flags */
  CheckArguments (&argc, argv);
  
  /* initialize internals */
  trace_init ();


  /* optional UDP */
  if (do_udp)
    udptrace_init ();

  /* get starting wallclock time */
  gettimeofday (&wallclock_start, NULL);

/* allocate all histo structs */
  create_all_histo ();


#ifndef TSTAT_RUNASLIB
  if (live_flag == FALSE)
    { //no remaing arg is live capture
      num_files = argc;
      fprintf (fp_stdout, "%d arg%s remaining, starting with '%s'\n",
	      num_files, num_files > 1 ? "s" : "", 
          (filenames) ? filenames[0] : "");
    }

  // knock, knock...
  fprintf (fp_stdout, "%s\n\n", VERSION);
#endif


  /*-----------------------------------------------------------*/
  /* RRDtools                                                   */
  /*   now that all the histo have been creaed, we may          */
  /*   parse rrdtool configuration file                         */
  if (rrdset_path && rrdset_conf) {
    rrd_engine = TRUE;
    rrdtool_init ();
  }
  /*-----------------------------------------------------------*/

  /* register the protocol analyzer over TCP/UDP */
  proto_init ();

  if (runtime_engine) {
    ini_read(runtime_conf_fname);
  }


  /* initialize bitrate struct */
  memset (&L3_bitrate, 0, sizeof (struct L3_bitrates));
  memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
  memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
  memset (&L7_udp_bitrate, 0, sizeof (struct L7_bitrates));
  
#ifndef TSTAT_RUNASLIB
  /* read each file in turn */
  if (live_flag == FALSE)
    {
      numfiles = argc;
      for (i = 0; i < argc; i++)
	{
	  if ((debug > 0) || (numfiles > 1))
	    {
	      if (argc > 1)
		fprintf (fp_stdout, "\nRunning file '%s' (%d of %d)\n",
			filenames[i], i + 1, numfiles);
	      else
		fprintf (fp_stdout, "Running file '%s'\n", filenames[i]);
	    }

	  /* do the real work */
	  ProcessFile (filenames[i], (i + 1 == numfiles));
	}
    }
  else
    {
      ProcessFile ("stdin", TRUE);	/* When live capture is on, no files are needed */
    }


  /* clean up output */
  if (printticks)
    fprintf (fp_stdout, "\n");

  /* get ending wallclock time */
  gettimeofday(&wallclock_finished, NULL);

  /* general output */
  fprintf(fp_stdout, "%lu packets seen, %lu TCP packets traced",
	   pnum, tcp_trace_count_outgoing + tcp_trace_count_incoming
	   + tcp_trace_count_local);
  if (do_udp)
    fprintf(fp_stdout, ", %lu UDP packets traced", udp_trace_count);
  fprintf(fp_stdout, "\n");

  /* actual tracefile times */
  etime = elapsed (first_packet, last_packet);
  fprintf(fp_stdout, "trace %s elapsed time: %s\n",
	   (num_files == 1) ? "file" : "files", elapsed2str (etime));
  if (debug > 0)
    {
      fprintf(fp_stdout, "\tfirst packet:  %s\n", ts2ascii (&first_packet));
      fprintf(fp_stdout, "\tlast packet:   %s\n", ts2ascii (&last_packet));
    }
  rrdtool_close ();
  exit(EXIT_SUCCESS);
#else
  return EXIT_SUCCESS;
#endif //TSTAT_RUNASLIB
}

void reopen_logfile(FILE **fp_ref, const char *basename, const char *filename)
{
  static char logfile[FILENAME_SIZE+50];

  snprintf (logfile,FILENAME_SIZE,"%s/%s", basename, filename);
  if (*fp_ref != NULL)
    fclose (*fp_ref);
  *fp_ref = fopen (logfile, "a");

  if (*fp_ref == NULL)
    {
      fprintf (fp_stderr, "Could not open file %s\n", logfile);
    }
}

int  write_tcplog_header_block(FILE *fp, int block, int base_column)
{
  int i,col;
  
  i = 0;
  col = base_column;

  switch(block)
   {
     case TCP_LOG_CORE:
        /*******************************
         * client stats
         *******************************/
       wfprintf(fp, "#c_ip:%d", col++); 	  // 1: ip address
       wfprintf(fp, " c_port:%d", col++);	  // 2: port 
       wfprintf(fp, " c_pkts_all:%d", col++);	  // 3: total number of segments uploaded
       wfprintf(fp, " c_rst_cnt:%d", col++);	  // 4: number of RST pkts sent
       wfprintf(fp, " c_ack_cnt:%d", col++);	  // 5: number of pkts with ACK flag set
       wfprintf(fp, " c_ack_cnt_p:%d", col++);    // 6: number of pure ACK pkts (i.e. ACK set but no payload)
       wfprintf(fp, " c_bytes_uniq:%d", col++);   // 7: number of unique bytes uploaded
       wfprintf(fp, " c_pkts_data:%d", col++);    // 8: number of segments with payload
       wfprintf(fp, " c_bytes_all:%d", col++);    // 9: total number of bytes = unique + retransmitted
       wfprintf(fp, " c_pkts_retx:%d", col++);    // 10: number of segments retransmitted
       wfprintf(fp, " c_bytes_retx:%d", col++);   // 11: number of bytes retransmitted
       wfprintf(fp, " c_pkts_ooo:%d", col++);	  // 12: number of packets out of order
       wfprintf(fp, " c_syn_cnt:%d", col++);	  // 13: number of segments with SYN set
       wfprintf(fp, " c_fin_cnt:%d", col++);	  // 14: number of segments with FIN set

        /*******************************
         * server stats
         *******************************/
       wfprintf(fp, " s_ip:%d", col++); 	  // 45: ip address
       wfprintf(fp, " s_port:%d", col++);	  // 46: port 
       wfprintf(fp, " s_pkts_all:%d", col++);	  // 47: total number of segments uploaded
       wfprintf(fp, " s_rst_cnt:%d", col++);	  // 48: number of RST pkts sent
       wfprintf(fp, " s_ack_cnt:%d", col++);	  // 49: number of pkts with ACK flag set
       wfprintf(fp, " s_ack_cnt_p:%d", col++);    // 50: number of pure ACK pkts (i.e. ACK set but no payload)
       wfprintf(fp, " s_bytes_uniq:%d", col++);   // 51: number of unique bytes
       wfprintf(fp, " s_pkts_data:%d", col++);    // 52: number of segments with payload
       wfprintf(fp, " s_bytes_all:%d", col++);    // 53: total number of bytes = unique + retransmitted
       wfprintf(fp, " s_pkts_retx:%d", col++);    // 54: number of segments retransmitted
       wfprintf(fp, " s_bytes_retx:%d", col++);   // 55: number of bytes retransmitted
       wfprintf(fp, " s_pkts_ooo:%d", col++);	  // 56: number of packets out of order
       wfprintf(fp, " s_syn_cnt:%d", col++);	  // 57: number of segments with SYN set
       wfprintf(fp, " s_fin_cnt:%d", col++);	  // 58: number of segments with FIN set

        /********************************
         * timestamps 
         ********************************/
       wfprintf(fp, " first:%d", col++);	// 90: first packet absolute
       wfprintf(fp, " last:%d", col++); 	// 91: last packet absolute
       wfprintf(fp, " durat:%d", col++);	// 89: completion time
       wfprintf(fp, " c_first:%d", col++);	// 92: first client packet since first flow segment
       wfprintf(fp, " s_first:%d", col++);	// 93: first server packet since first flow segment
       wfprintf(fp, " c_last:%d", col++);	// 94: last client packet since first flow segment
       wfprintf(fp, " s_last:%d", col++);	// 95: last server packet since first flow segment
       wfprintf(fp, " c_first_ack:%d", col++);  // 96: first client ack since first flow segment
       wfprintf(fp, " s_first_ack:%d", col++);  // 97: first server ack since first flow segment
       wfprintf(fp, " c_isint:%d", col++);	// 99: internal client ip
       wfprintf(fp, " s_isint:%d", col++);	// 100: internal server ip
       wfprintf(fp, " c_iscrypto:%d", col++);	// 99: internal client ip
       wfprintf(fp, " s_iscrypto:%d", col++);	// 100: internal server ip

        /********************************
         * basic L7 info 
         ********************************/
       wfprintf(fp, " con_t:%d", col++);	// 101: connection type
       break;
     case TCP_LOG_END_TO_END:
       wfprintf(fp, " c_rtt_avg:%d", col++);	  // 29: RTT average
       wfprintf(fp, " c_rtt_min:%d", col++);	  // 30: RTT minimum
       wfprintf(fp, " c_rtt_max:%d", col++);	  // 31: RTT maximum
       wfprintf(fp, " c_rtt_std:%d", col++);	  // 32: RTT standard deviation
       wfprintf(fp, " c_rtt_cnt:%d", col++);	  // 33: number of RTT valid samples
       wfprintf(fp, " c_ttl_min:%d", col++);	  // 34: TTL minimum
       wfprintf(fp, " c_ttl_max:%d", col++);	  // 35: TTL maximum

       wfprintf(fp, " s_rtt_avg:%d", col++);	  // 73: RTT average
       wfprintf(fp, " s_rtt_min:%d", col++);	  // 74: RTT minimum
       wfprintf(fp, " s_rtt_max:%d", col++);	  // 75: RTT maximum
       wfprintf(fp, " s_rtt_std:%d", col++);	  // 76: RTT standard deviation
       wfprintf(fp, " s_rtt_cnt:%d", col++);	  // 77: number of RTT valid samples
       wfprintf(fp, " s_ttl_min:%d", col++);	  // 78: TTL minimum
       wfprintf(fp, " s_ttl_max:%d", col++);	  // 79: TTL maximum
       break;
     case TCP_LOG_LAYER7:
       wfprintf(fp, " http_req_cnt:%d", col++);  // number of http requests (for HTTP flows)
       wfprintf(fp, " http_res_cnt:%d", col++);  // number of http responses (for HTTP flows)
       wfprintf(fp, " http_res:%d", col++);      // first http response code (for HTTP flows)

       wfprintf(fp, " c_pkts_push:%d", col++);   // number of client push separated messages
       wfprintf(fp, " s_pkts_push:%d", col++);   // number of server push separated messages

       wfprintf(fp, " c_tls_SNI:%d", col++);      // server name of TLS client hello message
       wfprintf(fp, " s_tls_SCN:%d", col++);      // subject name in TLS server certificate

       wfprintf(fp, " c_npnalpn:%d", col++);     // TLS Client Hello NPN/ALPN protocols bitmap
       wfprintf(fp, " s_npnalpn:%d", col++);     // TLS Server Hello NPN/ALPN protocols bitmap
       wfprintf(fp, " tls_session_stat:%d", col++);  // TLS Client/Server session negotiation bitmap

       wfprintf(fp, " c_last_handshakeT:%d", col++); // TLS client last packet seen before first Application Data time
       wfprintf(fp, " s_last_handshakeT:%d", col++); // TLS server last packet seen before first Application Data time

       wfprintf(fp, " c_appdataT:%d", col++);     // TLS client first Application Data time
       wfprintf(fp, " s_appdataT:%d", col++);     // TLS server first Application Data time

       wfprintf(fp, " c_appdataB:%d", col++);     // TLS client first Application Data rel seqno
       wfprintf(fp, " s_appdataB:%d", col++);     // TLS server first Application Data rel seqno
       
       wfprintf(fp, " fqdn:%d", col++);          // full qualified domain name
       wfprintf(fp, " dns_rslv:%d", col++);      // dns server ip address
       wfprintf(fp, " req_tm:%d", col++);        // absolute dns request time
       wfprintf(fp, " res_tm:%d", col++);        // absolute dns response time
       wfprintf(fp, " http_hostname:%d", col++); // first HTTP hostname (from Host:) if collected and present
       
       wfprintf(fp, " c_TLSvers:%d", col++); // first HTTP hostname (from Host:) if collected and present
       wfprintf(fp, " s_TLSvers:%d", col++); // first HTTP hostname (from Host:) if collected and present
       wfprintf(fp, " dns_enc:%d", col++);       // dns server ip address is encrypted
       break;
     case TCP_LOG_OPTIONS:
       wfprintf(fp, " c_f1323_opt:%d", col++);    // 15: window scale option (0/1)
       wfprintf(fp, " c_tm_opt:%d", col++);	  // 16: timestamp option (0/1)
       wfprintf(fp, " c_win_scl:%d", col++);	  // 17: window scale option
       wfprintf(fp, " c_sack_opt:%d", col++);	  // 18: SACK option (0/1)
       wfprintf(fp, " c_sack_cnt:%d", col++);	  // 19: number of SACK sent
       wfprintf(fp, " c_mss:%d", col++);	  // 20: maximum segment size declared
       wfprintf(fp, " c_mss_max:%d", col++);	  // 21: maximum segment size observed
       wfprintf(fp, " c_mss_min:%d", col++);	  // 22: minimum segment size observed
       wfprintf(fp, " c_win_max:%d", col++);	  // 23: maximum receiver window announced
       wfprintf(fp, " c_win_min:%d", col++);	  // 24: minimum receiver window announced
       wfprintf(fp, " c_win_0:%d", col++);	  // 25: number of segments with receiver window = 0
       wfprintf(fp, " c_cwin_max:%d", col++);	  // 26: congestion window max
       wfprintf(fp, " c_cwin_min:%d", col++);	  // 27: congestion window min
       wfprintf(fp, " c_cwin_ini:%d", col++);	  // 28: congestion window initial
       wfprintf(fp, " c_pkts_rto:%d", col++);	  // 36: number of segments retransmitted due to timeout
       wfprintf(fp, " c_pkts_fs:%d", col++);	  // 37: number of segments retransmitted due to fast retransmitt
       wfprintf(fp, " c_pkts_reor:%d", col++);    // 38: number of segments reordering
       wfprintf(fp, " c_pkts_dup:%d", col++);	  // 39: number of segments duplicated
       wfprintf(fp, " c_pkts_unk:%d", col++);	  // 40: number of segments not in sequence or duplicate which are not classified as specific events
       wfprintf(fp, " c_pkts_fc:%d", col++);	  // 41: number of segments retransmitted to probe receiver window
       wfprintf(fp, " c_pkts_unrto:%d", col++);   // 42: number of un-necessary transmission following a timeout
       wfprintf(fp, " c_pkts_unfs:%d", col++);    // 43: number of un-necessary transmission following fast retransmit
       wfprintf(fp, " c_syn_retx:%d", col++);	  // 44: retransmitted SYN with different initial seqno (0/1)

       wfprintf(fp, " s_f1323_opt:%d", col++);    // 59: window scale option (0/1)
       wfprintf(fp, " s_tm_opt:%d", col++);	  // 60: timestamp option (0/1)
       wfprintf(fp, " s_win_scl:%d", col++);	  // 61: window scale option
       wfprintf(fp, " s_sack_opt:%d", col++);	  // 62: SACK option (0/1)
       wfprintf(fp, " s_sack_cnt:%d", col++);	  // 63: number of SACK sent
       wfprintf(fp, " s_mss:%d", col++);	  // 64: maximum segment size declared
       wfprintf(fp, " s_mss_max:%d", col++);	  // 65: maximum segment size observed
       wfprintf(fp, " s_mss_min:%d", col++);	  // 66: minimum segment size observed
       wfprintf(fp, " s_win_max:%d", col++);	  // 67: maximum receiver window announced
       wfprintf(fp, " s_win_min:%d", col++);	  // 68: minimum receiver window announced
       wfprintf(fp, " s_win_0:%d", col++);	  // 69: number of segments with receiver window = 0
       wfprintf(fp, " s_cwin_max:%d", col++);	  // 70: congestion window max
       wfprintf(fp, " s_cwin_min:%d", col++);	  // 71: congestion window min
       wfprintf(fp, " s_cwin_ini:%d", col++);	  // 72: congestion window initial
       wfprintf(fp, " s_pkts_rto:%d", col++);	  // 80: number of segments retransmitted due to timeout
       wfprintf(fp, " s_pkts_fs:%d", col++);	  // 81: number of segments retransmitted due to fast retransmitt
       wfprintf(fp, " s_pkts_reor:%d", col++);    // 82: number of segments reordering
       wfprintf(fp, " s_pkts_dup:%d", col++);	  // 83: number of segments duplicated
       wfprintf(fp, " s_pkts_unk:%d", col++);	  // 84: number of segments not in sequence or duplicate which are not classified as specific events
       wfprintf(fp, " s_pkts_fc:%d", col++);	  // 85: number of segments retransmitted to probe receiver window
       wfprintf(fp, " s_pkts_unrto:%d", col++);   // 86: number of un-necessary transmission following a timeout
       wfprintf(fp, " s_pkts_unfs:%d", col++);    // 87: number of un-necessary transmission following fast retransmit
       wfprintf(fp, " s_syn_retx:%d", col++);	  // 88: retransmitted SYN with different initial seqno (0/1)
       break;
     case TCP_LOG_ADVANCED:
#ifdef PACKET_STATS
       /*******************************
        * PSH-delimited Message sizes 
        *******************************/
       wfprintf(fp, " c_msgsize_count:%d", col++); 
       for (i=0;i<MAX_COUNT_MESSAGES;i++) 
           wfprintf(fp, " c_msgsize%d:%d", i+1, col++);

       wfprintf(fp, " s_msgsize_count:%d", col++);	 // number of valid samples (out of MAX_COUNT_MESSAGES)
       for (i=0;i<MAX_COUNT_MESSAGES;i++) 
           wfprintf(fp, " s_msgsize%d:%d", i+1, col++);

       /*******************************
        * segment sizes 
        *******************************/
       wfprintf(fp, " c_pktsize_count:%d", col++);   // number of valid samples (out of MAX_COUNT_SEGMENTS)
       for (i=0;i<MAX_COUNT_SEGMENTS;i++) 
         wfprintf (fp, " c_pktsize%d:%d", i+1, col++);

       wfprintf(fp, " s_pktsize_count:%d", col++);	 // number of valid samples (out of MAX_COUNT_SEGMENTS)
       for (i=0;i<MAX_COUNT_SEGMENTS;i++) 
         wfprintf (fp, " s_pktsize%d:%d", i+1, col++);

       /*******************************
        * segment intertimes
        *******************************/
       for (i=0; i < MAX_COUNT_SEGMENTS-1; i++)
           wfprintf (fp, " c_sit%d:%d", i+1, col++);

       for (i=0;i<MAX_COUNT_SEGMENTS-1;i++)
           wfprintf (fp, " s_sit%d:%d", i+1, col++);

       /*******************************
        * averages
        *******************************/
       wfprintf (fp, " c_pkts_data:%d", col++);
       wfprintf (fp, " c_pkts_data_avg:%d", col++);
       wfprintf (fp, " c_pkts_data_std:%d", col++);
       wfprintf (fp, " s_pkts_data:%d", col++);
       wfprintf (fp, " s_pkts_data_avg:%d", col++);
       wfprintf (fp, " s_pkts_data_std:%d", col++);

       wfprintf (fp, " c_seg_cnt:%d", col++);
       wfprintf (fp, " c_sit_avg:%d", col++);
       wfprintf (fp, " c_sit_std:%d", col++);

       wfprintf (fp, " s_seg_cnt:%d", col++);
       wfprintf (fp, " s_sit_avg:%d", col++);
       wfprintf (fp, " s_sit_std:%d", col++);

       /******************************
        * PSH
        ******************************/
       wfprintf(fp, " c_pkts_push:%d", col++);
       wfprintf(fp, " s_pkts_push:%d", col++);
#endif
       break;
     default:
       break;
   }
 return col;
} 

void write_log_header(FILE *fp, int log_type)
{
  int i, col;

  /*****************************************************
   * LOG_TCP_COMPLETE + LOG_TCP_NOCOMPLETE
   *****************************************************/
  if (log_type == LOG_TCP_COMPLETE)
   {
     col = 1;
     wfprintf (fp, "#%02d",log_level);   /* Level coded at the start of the header line */

     /* Core Tstat TCP measurements for both log_tcp_complete and log_tcp_nocomplete */
     col = write_tcplog_header_block(fp,TCP_LOG_CORE,col);

     if (log_level & TCP_LOG_END_TO_END)
       col = write_tcplog_header_block(fp,TCP_LOG_END_TO_END,col);

     if (log_level & TCP_LOG_OPTIONS)
       col = write_tcplog_header_block(fp,TCP_LOG_OPTIONS,col);

     if (log_level & TCP_LOG_LAYER7)
       col = write_tcplog_header_block(fp,TCP_LOG_LAYER7,col);

     if (log_level & TCP_LOG_ADVANCED)
       col = write_tcplog_header_block(fp,TCP_LOG_ADVANCED,col);

     wfprintf (fp, "\n");
   }
  else if (log_type == LOG_TCP_NOCOMPLETE)
   {
     col = 1;
     wfprintf (fp, "#%02d",log_level);   /* Level coded at the start of the header line */

     /* Core Tstat TCP measurements only for log_tcp_nocomplete */
     col = write_tcplog_header_block(fp,TCP_LOG_CORE,col);

     wfprintf (fp, "\n");
   }

    /**************************************************
     * LOG_UDP_COMPLETE
     **************************************************/
  else if (log_type == LOG_UDP_COMPLETE)
   {
     col = 1;
     wfprintf(fp, "#c_ip:%d", col++);		 // client ip
     wfprintf(fp, " c_port:%d", col++); 	 // client port
     wfprintf(fp, " c_first_abs:%d", col++);	 // first time absolute
     wfprintf(fp, " c_durat:%d", col++);	 // connection duration
     wfprintf(fp, " c_bytes_all:%d", col++);	 // bytes uploaded
     wfprintf(fp, " c_pkts_all:%d", col++);	 // packets uploaded
     wfprintf(fp, " c_isint:%d", col++);	 // client ip is internal
     wfprintf(fp, " c_iscrypto:%d", col++);	 // client ip is internal
     wfprintf(fp, " c_type:%d", col++); 	 // flow type
     wfprintf(fp, " s_ip:%d", col++);		 // server ip
     wfprintf(fp, " s_port:%d", col++); 	 // server port
     wfprintf(fp, " s_first_abs:%d", col++);	 // first time absolute
     wfprintf(fp, " s_durat:%d", col++);	 // connection duration
     wfprintf(fp, " s_bytes_all:%d", col++);	 // bytes downloaded
     wfprintf(fp, " s_pkts_all:%d", col++);	 // packets downloaded
     wfprintf(fp, " s_isint:%d", col++);	 // server ip is internal
     wfprintf(fp, " s_iscrypto:%d", col++);	 // server ip is internal
     wfprintf(fp, " s_type:%d", col++); 	 // flow type
        wfprintf (fp, " fqdn:%d", col++);
     wfprintf (fp, " quic_SNI:%d", col++);
     wfprintf (fp, " quic_UA:%d", col++);
     wfprintf (fp, " quic_c_vers:%d", col++);
     wfprintf (fp, " quic_s_vers:%d", col++);
     wfprintf (fp, " quic_zero_rtt:%d", col++);
     wfprintf (fp, " quic_ech:%d", col++);
#ifdef PACKET_STATS
       /*******************************
        * segment sizes 
        *******************************/
       wfprintf(fp, " c_pktsize_count:%d", col++);   // number of valid samples (out of MAX_COUNT_SEGMENTS)
       for (i=0;i<MAX_COUNT_SEGMENTS;i++) 
         wfprintf (fp, " c_pktsize%d:%d", i+1, col++);

       wfprintf(fp, " s_pktsize_count:%d", col++);	 // number of valid samples (out of MAX_COUNT_SEGMENTS)
       for (i=0;i<MAX_COUNT_SEGMENTS;i++) 
         wfprintf (fp, " s_pktsize%d:%d", i+1, col++);

       /*******************************
        * segment intertimes
        *******************************/
       for (i=0; i < MAX_COUNT_SEGMENTS-1; i++)
           wfprintf (fp, " c_sit%d:%d", i+1, col++);

       for (i=0;i<MAX_COUNT_SEGMENTS-1;i++)
           wfprintf (fp, " s_sit%d:%d", i+1, col++);

       /*******************************
        * averages
        *******************************/
       wfprintf (fp, " c_pkts_data:%d", col++);
       wfprintf (fp, " c_pkts_data_avg:%d", col++);
       wfprintf (fp, " c_pkts_data_std:%d", col++);
       wfprintf (fp, " s_pkts_data:%d", col++);
       wfprintf (fp, " s_pkts_data_avg:%d", col++);
       wfprintf (fp, " s_pkts_data_std:%d", col++);

       wfprintf (fp, " c_seg_cnt:%d", col++);
       wfprintf (fp, " c_sit_avg:%d", col++);
       wfprintf (fp, " c_sit_std:%d", col++);

       wfprintf (fp, " s_seg_cnt:%d", col++);
       wfprintf (fp, " s_sit_avg:%d", col++);
       wfprintf (fp, " s_sit_std:%d", col++);
#endif

     wfprintf (fp, "\n");
   }

    /**************************************************
     * LOG_HTTP_COMPLETE
     **************************************************/
  else if (log_type == LOG_HTTP_COMPLETE) 
   {
     col = 1;
     /************************
      * client side
      ************************/
     wfprintf (fp,"#C#c_ip:%d",col++);		// 1: client ip
     wfprintf (fp,"\tc_port:%d",col++);		// 2: client port
     /************************
      * server side
      ************************/
     wfprintf (fp,"\ts_ip:%d",col++);		// 3: server ip
     wfprintf (fp,"\ts_port:%d",col++);		// 4: server port
     /************************
      * Info
      ************************/
     wfprintf (fp,"\ttime_abs:%d",col++); 	// 5: absolute packet time
     wfprintf (fp,"\tmethod:%d",col++);		// 6: method
     wfprintf (fp,"\thostname:%d",col++); 	// 7: hostname
     wfprintf(fp, "\tfqdn:%d", col++);          // 8: full qualified domain name
     wfprintf (fp,"\tpath:%d",col++);	        // 8: path
     wfprintf (fp,"\treferer:%d",col++);  	// 9: referer
     wfprintf (fp,"\tuser_agent:%d",col++);	// 10: user agent
     wfprintf (fp,"\tcookie:%d",col++);		// 11: cookie
     wfprintf (fp,"\tdnt:%d",col++);		// 12: do not track me
     wfprintf(fp, "\n");

     col = 1;
     /************************
      * server side
      ************************/
     wfprintf (fp,"#S#c_ip:%d",col++);		// 1: client ip
     wfprintf (fp,"\tc_port:%d",col++);		// 2: client port
     /************************
      * server side
      ************************/
     wfprintf (fp,"\ts_ip:%d",col++);		// 3: server ip
     wfprintf (fp,"\ts_port:%d",col++);		// 4: server port
     /************************
      * Info
      ************************/
     wfprintf (fp,"\ttime_abs:%d",col++); 	// 5: absolute packet time
     wfprintf (fp,"\tHTTP:%d",col++);		// 6: protocol
     wfprintf (fp,"\tresponse:%d",col++); 	// 7: response code
     wfprintf (fp,"\tcontent_len:%d",col++);	// 8: content lenght
     wfprintf (fp,"\tcontent_type:%d",col++);	// 9: content type
     wfprintf (fp,"\tserver:%d",col++);  	// 10: server
     wfprintf (fp,"\trange:%d",col++);		// 11: range
     wfprintf (fp,"\tlocation:%d",col++);	// 12: location
     wfprintf (fp,"\tset_cookie:%d",col++);		// 13: cookie
     wfprintf(fp, "\n");
   }

  else if (log_type == LOG_DNS_COMPLETE) 
   {
    col = 1;
    wfprintf (fp,"#c_ip:%d",col++);	
    wfprintf (fp," c_port:%d",col++);	
    wfprintf (fp," c_isint:%d",col++);	
    wfprintf (fp," c_iscrypto:%d",col++);	
    wfprintf (fp," s_ip:%d",col++);	
    wfprintf (fp," s_port:%d",col++);	
    wfprintf (fp," s_isint:%d",col++);	
    wfprintf (fp," s_iscrypto:%d",col++);	
    wfprintf (fp," time:%d",col++);	
    wfprintf (fp," entry:%d",col++);	
    wfprintf (fp," trans_id:%d",col++);	
    wfprintf (fp," query:%d",col++);	
    wfprintf (fp," ttl:%d",col++);	
    wfprintf (fp," class:%d",col++);	
    wfprintf (fp," type:%d",col++);	
    wfprintf (fp," answer:%d",col++);	
    wfprintf (fp," flags:%d",col++);	
    wfprintf (fp," qdcount:%d",col++);	
    wfprintf (fp," ancount:%d",col++);	
    wfprintf (fp," nscount:%d",col++);	
    wfprintf (fp," arcount:%d",col++);	
    wfprintf (fp," pkt_size:%d",col++);	
    wfprintf(fp, "\n");
   }

   else if (log_type == LOG_MM_COMPLETE)
   {
     col = 1;
//     wfprintf(fp,"#t_proto:%d", col++);		 // 1: Transport Prototol (TCP/UDP)
     wfprintf(fp,"#a_proto:%d", col++);		 // 1: Application Prototol (RTP/RTCP)
     /* */
     wfprintf(fp," direction:%d", col++);		 // 2:  Client Protocol
/* Client Info */
     wfprintf(fp," c_proto:%d", col++);		 // 2:  Client Protocol (RTP+/None)
     wfprintf(fp," c_ip:%d", col++);		 // 3:  client ip
     wfprintf(fp," c_port:%d", col++);		 // 4:  client port
     wfprintf(fp," c_internal:%d", col++);	 // 5:  client is internal
     wfprintf(fp," c_iscrypto:%d", col++);	 // 5:  client is internal
     wfprintf(fp," c_mux_prot:%d", col++);	 // 5:  client is internal
     wfprintf(fp," s_proto:%d", col++);		 // 
     wfprintf(fp," s_ip:%d", col++);		 // 
     wfprintf(fp," s_port:%d", col++);		 // 
     wfprintf(fp," s_internal:%d", col++);	 // 
     wfprintf(fp," s_iscrypto:%d", col++);	 // 
     wfprintf(fp," s_mux_prot:%d", col++);	 // 5:  client is internal
     /* */
     wfprintf(fp," packets:%d", col++);	 // 6:  client packets
     wfprintf(fp," ipg:%d", col++);		 // 7:  client Inter Packet Gap
     wfprintf(fp," jitter_avg:%d", col++);	 // 8:  client jitter (average)
     wfprintf(fp," jitter_max:%d", col++);	 // 9:  client jitter (max)
     wfprintf(fp," jitter_min:%d", col++);	 // 10: client jitter (min)
     wfprintf(fp," ttl_avg:%d", col++);	 // 11: client TTL (average)
     wfprintf(fp," ttl_max:%d", col++);	 // 12: client TTL (max)
     wfprintf(fp," ttl_min:%d", col++);	 // 13: client TTL (min)
     wfprintf(fp," starttime:%d", col++);	 // 14: client start time (epoch)
     wfprintf(fp," duration:%d", col++);	 // 15: client duration
     wfprintf(fp," databytes:%d", col++);	 // 16: client data transfered
     wfprintf(fp," speed:%d", col++);		 // 17: client average speed
     wfprintf(fp," SSRC:%d", col++);		 // 18: client RTP/RTCP SSRC
     wfprintf(fp," losses:%d", col++);	 // 19: client RTP lost packets
     wfprintf(fp," oos:%d", col++);		 // 20: client RTP out-of-sequence
     wfprintf(fp," dup:%d", col++);		 // 21: client RTP duplicates
     wfprintf(fp," late:%d", col++);		 // 22: client RTP lage
     wfprintf(fp," pt_id:%d", col++);		 // 23: client RTP Packet Type
     wfprintf(fp," pt_counters:%d", col++);		 // 23: client RTP Packet Type
     wfprintf(fp," bogus:%d", col++);		 // 24: client bocus reset
     wfprintf(fp," rtcp_losses:%d", col++);	 // 25: client RTCP cumulative loss
     wfprintf(fp," rtcp_fraclost:%d", col++);	 // 26: client RTCP fraction lost
     wfprintf(fp," rtcp_lenpack:%d", col++);	 // 27: client RTCP flow length [packets]
     wfprintf(fp," rtcp_lenbytes:%d", col++);	 // 28: client RTCP flow length [bytes]
     wfprintf(fp," rtt_avg:%d", col++);	 // 29: client RTT average
     wfprintf(fp," rtt_max:%d", col++);	 // 30: client RTT max
     wfprintf(fp," rtt_min:%d", col++);	 // 31: client RTT min
     wfprintf(fp," rtt_samples:%d", col++);	 // 32: client RTT samples
     wfprintf(fp," rtcp_trunc:%d", col++);	 // 33: client RTCP truncated header

     wfprintf(fp," rtp_max_payload:%d", col++);	 // 
     wfprintf(fp," rtp_min_payload:%d", col++);	 // 
     wfprintf(fp," rtp_avg_payload:%d", col++);	 // 
     wfprintf(fp," rtp_stdev_payload:%d", col++);	 // 
     
     wfprintf(fp," jitter8k_avg:%d", col++);	 // 8:  client jitter (average)
     wfprintf(fp," jitter8k_max:%d", col++);	 // 9:  client jitter (max)
     wfprintf(fp," jitter8k_min:%d", col++);	 // 10: client jitter (min)
     wfprintf(fp," jitter90k_avg:%d", col++);	 // 8:  client jitter (average)
     wfprintf(fp," jitter90k_max:%d", col++);	 // 9:  client jitter (max)
     wfprintf(fp," jitter90k_min:%d", col++);	 // 10: client jitter (min)
     wfprintf (fp, "\n");
   }

    /**************************************************
     * LOG_PERIODIC
     **************************************************/
  else if (log_type == LOG_TCP_PERIODIC) 
   {
     col = 1;


       wfprintf(fp, "#c_ip:%d", col++); 	  // 1: ip address
       wfprintf(fp, " c_port:%d", col++);	  // 2: port 
       wfprintf(fp, " s_ip:%d", col++); 	  // 45: ip address
       wfprintf(fp, " s_port:%d", col++);	  // 46: port 

        /********************************
         * timestamps 
         ********************************/
       wfprintf(fp, " time_abs_start:%d", col++);	// 90: first packet absolute
       wfprintf(fp, " time_rel_start:%d", col++);	// 90: first packet absolute
       wfprintf(fp, " time_rel_end:%d", col++); 	// 91: last packet absolute
       wfprintf(fp, " bin_duration:%d", col++); 	// 91: last packet absolute

       wfprintf(fp, " c_pkts_all:%d", col++);	  // 3: total number of segments uploaded
       wfprintf(fp, " c_rst_cnt:%d", col++);	  // 4: number of RST pkts sent
       wfprintf(fp, " c_ack_cnt:%d", col++);	  // 5: number of pkts with ACK flag set
       wfprintf(fp, " c_ack_cnt_p:%d", col++);    // 6: number of pure ACK pkts (i.e. ACK set but no payload)
       wfprintf(fp, " c_bytes_uniq:%d", col++);   // 7: number of unique bytes uploaded
       wfprintf(fp, " c_pkts_data:%d", col++);    // 8: number of segments with payload
       wfprintf(fp, " c_bytes_all:%d", col++);    // 9: total number of bytes = unique + retransmitted
       wfprintf(fp, " c_pkts_retx:%d", col++);    // 10: number of segments retransmitted
       wfprintf(fp, " c_bytes_retx:%d", col++);   // 11: number of bytes retransmitted
       wfprintf(fp, " c_pkts_ooo:%d", col++);	  // 12: number of packets out of order
       wfprintf(fp, " c_syn_cnt:%d", col++);	  // 13: number of segments with SYN set
       wfprintf(fp, " c_fin_cnt:%d", col++);	  // 14: number of segments with FIN set

        /*******************************
         * server stats
         *******************************/
       wfprintf(fp, " s_pkts_all:%d", col++);	  // 47: total number of segments uploaded
       wfprintf(fp, " s_rst_cnt:%d", col++);	  // 48: number of RST pkts sent
       wfprintf(fp, " s_ack_cnt:%d", col++);	  // 49: number of pkts with ACK flag set
       wfprintf(fp, " s_ack_cnt_p:%d", col++);    // 50: number of pure ACK pkts (i.e. ACK set but no payload)
       wfprintf(fp, " s_bytes_uniq:%d", col++);   // 51: number of unique bytes
       wfprintf(fp, " s_pkts_data:%d", col++);    // 52: number of segments with payload
       wfprintf(fp, " s_bytes_all:%d", col++);    // 53: total number of bytes = unique + retransmitted
       wfprintf(fp, " s_pkts_retx:%d", col++);    // 54: number of segments retransmitted
       wfprintf(fp, " s_bytes_retx:%d", col++);   // 55: number of bytes retransmitted
       wfprintf(fp, " s_pkts_ooo:%d", col++);	  // 56: number of packets out of order
       wfprintf(fp, " s_syn_cnt:%d", col++);	  // 57: number of segments with SYN set
       wfprintf(fp, " s_fin_cnt:%d", col++);	  // 58: number of segments with FIN set


        /********************************
         * basic L7 info 
         ********************************/

       wfprintf(fp, " c_rtt_avg:%d", col++);	  // 29: RTT average
       wfprintf(fp, " c_rtt_cnt:%d", col++);	  // 33: number of RTT valid samples
       wfprintf(fp, " s_rtt_avg:%d", col++);	  // 73: RTT average
       wfprintf(fp, " s_rtt_cnt:%d", col++);	  // 77: number of RTT valid samples

       // CWND
       wfprintf(fp, " c_cwin_min:%d", col++);
       wfprintf(fp, " c_cwin_max:%d", col++);
       wfprintf(fp, " s_cwin_min:%d", col++);
       wfprintf(fp, " s_cwin_max:%d", col++);

       // Sacks
       wfprintf(fp, " c_sack_cnt:%d", col++);
       wfprintf(fp, " s_sack_cnt:%d", col++);

       // Internal and Crypto
       wfprintf(fp," c_isint:%d", col++);
       wfprintf(fp," s_isint:%d", col++);
       wfprintf(fp," c_iscrypto:%d", col++);
       wfprintf(fp," s_iscrypto:%d", col++);

       wfprintf (fp, "\n");
   }

    /**************************************************
     * LOG_PERIODIC_UDP
     **************************************************/
 else if (log_type == LOG_UDP_PERIODIC) 
   {
     col = 1;
     wfprintf(fp, "#c_ip:%d", col++);		 // client ip
     wfprintf(fp, " c_port:%d", col++); 	 // client port
     wfprintf(fp, " c_isint:%d", col++);	 // client ip is internal
     wfprintf(fp, " c_iscrypto:%d", col++);	 // client ip is internal

     
     wfprintf(fp, " s_ip:%d", col++);		 // server ip
     wfprintf(fp, " s_port:%d", col++); 	 // server port
     wfprintf(fp, " s_isint:%d", col++);	 // server ip is internal
     wfprintf(fp, " s_iscrypto:%d", col++);	 // server ip is internal

        /********************************
         * timestamps 
         ********************************/
       wfprintf(fp, " time_abs_start:%d", col++);	// 90: first packet absolute
       wfprintf(fp, " time_rel_start:%d", col++);	// 90: first packet absolute
       wfprintf(fp, " time_rel_end:%d", col++); 	// 91: last packet absolute
       wfprintf(fp, " bin_duration:%d", col++); 	// 91: last packet absolute

     wfprintf(fp, " c_pkts_all:%d", col++);	  // 3: total number of segments uploaded
     wfprintf(fp, " c_bytes_all:%d", col++);    // 9: total number of bytes = unique 
     wfprintf(fp, " s_pkts_all:%d", col++);	  // 47: total number of segments uploaded
     wfprintf(fp, " s_bytes_all:%d", col++);    // 53: total number of bytes = unique + retransmitted

     wfprintf (fp, "\n");
   }
   
}

char * old_filename;

// MGM
/* Create subdirs into which out files will be put */
void
create_new_outfiles (char *input_filename, Bool reuse_dir)
{
  char tmpstr[FILENAME_SIZE+20];
  struct stat fbuf;
  char date[1000];
  char * filename;

  if (input_filename==NULL)filename = old_filename;
  else {
	old_filename = strdup(input_filename);
	filename = old_filename;
}

  if (!log_bitmask && !runtime_engine)
    return;

  if (reuse_dir == FALSE) {
      if (!basedirspecified) {
          /* get the basename from the tracefile */
          if (is_stdin || strcmp(filename, "TSTAT_RUNASLIB") == 0) {
              basenamedir = strdup ("stdin");
          } else {
              basenamedir = strdup (filename);
          }
      }
      if (stat (basenamedir, &fbuf) != 0) {
	  sprintf(date, "mkdir -p %s", basenamedir);
	  system(date);
          //mkdir (basenamedir, 0775);
      }
      else {
             if (S_ISREG(fbuf.st_mode)){
             	basenamedir = realloc (basenamedir, strlen (basenamedir) + 5 );
		strcat(basenamedir, ".out");
	  	sprintf(date, "mkdir -p %s", basenamedir);
	 	system(date);
             }
      }
      strftime (date, 49, "%Y_%m_%d_%H_%M", localtime (&current_time.tv_sec));
      sprintf (basename, "%s/%s.out", basenamedir, date);
      if (stat (basename, &fbuf) != -1) {
          /* remove the previous directory */
          sprintf (tmpstr, "rm -rf %s", basename);
          system (tmpstr);
      }
      if (mkdir (basename, 0775) == -1) {
          fprintf(fp_stderr, "Cannot create directory %s\n", basename);
      }
      fprintf(fp_stdout, "[%s] created new outdir %s\n", Timestamp(), basename);
  }

  if (LOG_IS_ENABLED(LOG_TCP_COMPLETE)) {
      reopen_logfile(&fp_logc,basename,"log_tcp_complete");
      write_log_header(fp_logc, LOG_TCP_COMPLETE);
  }


  if (LOG_IS_ENABLED(LOG_TCP_NOCOMPLETE)) {
      reopen_logfile(&fp_lognc,basename,"log_tcp_nocomplete");
      write_log_header(fp_lognc, LOG_TCP_NOCOMPLETE);
  }

  if (LOG_IS_ENABLED(LOG_MM_COMPLETE)) {
      reopen_logfile(&fp_rtp_logc, basename, "log_mm_complete");
      write_log_header(fp_rtp_logc, LOG_MM_COMPLETE);
  }

  if (LOG_IS_ENABLED(LOG_UDP_COMPLETE)) {
      reopen_logfile(&fp_udp_logc,basename,"log_udp_complete");
      write_log_header(fp_udp_logc, LOG_UDP_COMPLETE);
  }

  if (LOG_IS_ENABLED(LOG_HTTP_COMPLETE)) {
      reopen_logfile(&fp_http_logc,basename,"log_http_complete");
      write_log_header(fp_http_logc,LOG_HTTP_COMPLETE);
  }

  if (LOG_IS_ENABLED(LOG_TCP_PERIODIC)) {
      reopen_logfile(&fp_periodic_logc,basename,"log_tcp_periodic");
      write_log_header(fp_periodic_logc, LOG_TCP_PERIODIC);
  }

  if (LOG_IS_ENABLED(LOG_UDP_PERIODIC)) {
      reopen_logfile(&fp_periodic_udp_logc,basename,"log_udp_periodic");
      write_log_header(fp_periodic_udp_logc, LOG_UDP_PERIODIC);
  }

  if (LOG_IS_ENABLED(LOG_DNS_COMPLETE)) {
      reopen_logfile(&fp_dns_logc,basename,"log_dns_complete");
      write_log_header(fp_dns_logc,LOG_DNS_COMPLETE);
  }

    if (runtime_engine)
        dump_create_outdir(basename);
}

void close_all_logfiles()
{
  if (fp_logc != NULL) { fclose(fp_logc); fp_logc=NULL; }
  if (fp_lognc != NULL) { fclose(fp_lognc); fp_lognc=NULL; }

  if (fp_rtp_logc != NULL) { fclose(fp_rtp_logc); fp_rtp_logc=NULL; }
  if (fp_udp_logc != NULL) { fclose(fp_udp_logc); fp_udp_logc=NULL; }
  if (fp_http_logc != NULL) { fclose(fp_http_logc); fp_http_logc=NULL; }
  if (fp_dns_logc != NULL) { fclose(fp_dns_logc); fp_dns_logc=NULL; }
}

void ip_histo_stat(struct ip *pip)
{
  /* Code for the update of IP histograms */
  
  if (internal_src && !internal_dst)
    {
      L4_bitrate.out[IP_TYPE] += ntohs (pip->ip_len);
      if (pip->ip_p == IPPROTO_ICMP)
    	L4_bitrate.out[ICMP_TYPE] += ntohs (pip->ip_len);
      add_histo (ip_protocol_out, pip->ip_p);
      /* For TCP and UDP the L3_bitrate is computed elsewhere */
      if (pip->ip_p==IPPROTO_TCP)
       { 
         add_histo (L3_protocol_out,L3_IPv4_TCP); 
       }
      else if (pip->ip_p==IPPROTO_UDP)
       { 
         add_histo (L3_protocol_out,L3_IPv4_UDP); 
       }
      else 
       { 
	 L3_bitrate.out[L3_IPv4_OTHER] += ntohs (pip->ip_len);
         add_histo (L3_protocol_out,L3_IPv4_OTHER); 
       }

      add_histo (ip_len_out, (float) ntohs (pip->ip_len));
      add_histo (ip_ttl_out, (float) pip->ip_ttl);
      add_histo (ip_tos_out, (float) pip->ip_tos);

    }
  else if (!internal_src && internal_dst)
    {
      L4_bitrate.in[IP_TYPE] += ntohs (pip->ip_len);
      if (pip->ip_p == IPPROTO_ICMP)
    	L4_bitrate.in[ICMP_TYPE] += ntohs (pip->ip_len);
      add_histo (ip_protocol_in, pip->ip_p);
      /* For TCP and UDP the L3_bitrate is computed elsewhere */
      if (pip->ip_p==IPPROTO_TCP)
       { 
         add_histo (L3_protocol_in,L3_IPv4_TCP); 
       }
      else if (pip->ip_p==IPPROTO_UDP)
       { 
         add_histo (L3_protocol_in,L3_IPv4_UDP); 
       }
      else 
       { 
	 L3_bitrate.in[L3_IPv4_OTHER] += ntohs (pip->ip_len);
         add_histo (L3_protocol_in,L3_IPv4_OTHER); 
       }
      add_histo (ip_len_in, (float) ntohs (pip->ip_len));
      add_histo (ip_ttl_in, (float) pip->ip_ttl);
      add_histo (ip_tos_in, (float) pip->ip_tos);
    }
  else if (internal_src && internal_dst)
    {
      L4_bitrate.loc[IP_TYPE] += ntohs (pip->ip_len);
      if (pip->ip_p == IPPROTO_ICMP)
    	L4_bitrate.loc[ICMP_TYPE] += ntohs (pip->ip_len);
      add_histo (ip_protocol_loc, pip->ip_p);
      /* For TCP and UDP the L3_bitrate is computed elsewhere */
      if (pip->ip_p==IPPROTO_TCP)
       { 
         add_histo (L3_protocol_loc,L3_IPv4_TCP); 
       }
      else if (pip->ip_p==IPPROTO_UDP)
       { 
         add_histo (L3_protocol_loc,L3_IPv4_UDP); 
       }
      else 
       { 
	 L3_bitrate.loc[L3_IPv4_OTHER] += ntohs (pip->ip_len);
         add_histo (L3_protocol_loc,L3_IPv4_OTHER); 
       }
      add_histo (ip_len_loc, (float) ntohs (pip->ip_len));
      add_histo (ip_ttl_loc, (float) pip->ip_ttl);
      add_histo (ip_tos_loc, (float) pip->ip_tos);
    }
}

inline static int
ip_header_stat (int phystype, 
                struct ip *pip, 
                u_long *fpnum, 
                u_long *pcount,
		        int file_count, 
                char *filename, 
                long int location, 
                int tlen,
		void *plast,
		int ip_direction)
{
  /* another sanity check, only understand ETHERNET right now */

  if (phystype != PHYS_ETHER)
    {
      static int not_ether = 0;

      ++not_ether;
      if (not_ether < 5)
	{
	  fprintf(fp_stderr,
		   "Skipping packet %lu, not an ethernet packet\n", pnum);
	}			/* else, just shut up */
      return 0;
    }

  if (PIP_ISV6 (pip))
    {

      //fprintf(fp_stderr,"IPv6 packet \n");
      //It does all the statistics about IPv6 packets

      /*IPv6 SUPPORT */
      IPv6_support (pip, plast,ip_direction);

      // We must set this in a suitable way, possibly inside IPv6_support
      crypto_src = crypto_ipv6 (PIP_V6(pip)->ip6_saddr);
      crypto_dst = crypto_ipv6 (PIP_V6(pip)->ip6_daddr);

    }				//if it isnt an IPv6 packet I do statistics thinking that it's an IPv4
  else
    {
      /* decide wheater this is internal or external */
      {
        if(mac_filter.tot_internal_eth >0 )
        {
        /* going to use the Ethernet MAC here */
	  internal_src = internal_shost;
	  internal_dst = internal_dhost;
        }
        else
	{
         /* stick with ip networks - or trust what you have been told */
	 switch(ip_direction)
	  {
           case SRC_IN_DST_IN:
   	    internal_src = 1;
	    internal_dst = 1;
	    break;
           case SRC_IN_DST_OUT:
   	    internal_src = 1;
	    internal_dst = 0;
	    break;
           case SRC_OUT_DST_IN:
   	    internal_src = 0;
	    internal_dst = 1;
	    break;
           case SRC_OUT_DST_OUT:
   	    internal_src = 0;
	    internal_dst = 0;
	    break;
           case DEFAULT_NET:
           default:
   	    internal_src = internal_ip (pip->ip_src);
	    internal_dst = internal_ip (pip->ip_dst);
	    break;
	  }
	}
      }

      /* .a.c. */

      crypto_src = crypto_ip (pip->ip_src);
      crypto_dst = crypto_ip (pip->ip_dst);
      
      /* 
         Histograms done only if packet is not duplicated, 
         so code is executed in ProcessPacket after the TCP/UDP processing
      */
      
      /* ip_histo_stat(pip); */

      /* Now it is safe to apply internal IP addresses obfuscation */
      if (internal_src)
          pip->ip_src.s_addr ^= ip_obfuscate_mask;
      if (internal_dst)
          pip->ip_dst.s_addr ^= ip_obfuscate_mask;          

    }
  /* update global and per-file packet counters */
  ++pnum;			/* global */
  ++(*fpnum);			/* local to this file */
  ++(*pcount);			/* counter per chiudere i pendenti */

  /* the last_time_step is assigned only at the first packet */
  if (first_ip_packet == TRUE)
   {
    first_ip_packet = FALSE;
    last_time_step = last_cleaned = current_time;
   }

  /* check for re-ordered packets */
  if (!ZERO_TIME (&last_packet))
    {
      if (elapsed (last_packet, current_time) < 0)
	{
	  /* out of order */
	  if ((file_count > 1) && ((*fpnum) == 1))
	    {
	      fprintf (fp_stderr, 
            "Warning, first packet in file %s comes BEFORE the last packet\n"
            "in the previous file.  That will likely confuse the program, please\n"
            "order the files in time if you have trouble\n", filename);
	    }
	  else
	    {
	      static int warned = 0;

	      if (warn_ooo)
		{
		  fprintf (fp_stderr, 
            "Warning, packet %ld in file %s comes BEFORE the previous packet\n"
            "That will likely confuse the program, so be careful!\n", 
            (*fpnum), filename);
		}
	      else if (!warned)
		{
		  fprintf (fp_stderr, 
            "Packets in file %s are out of order.\n"
            "That will likely confuse the program, so be careful!\n", 
            filename);
		}
	      warned = 1;
	    }

	}
    }


#ifndef TSTAT_RUNASLIB
  /* install signal handler */
  if ((*fpnum) == 1)
    {
      signal (SIGINT, QuitSig);
      signal (SIGUSR1, Usr1Sig);
    }
#endif

#ifndef TSTAT_RUNASLIB
  /* progress counters */
  if (printticks)
    {
      if ((((*fpnum) < 100) && ((*fpnum) % 10 == 0)) ||
	  (((*fpnum) < 1000) && ((*fpnum) % 100 == 0)) ||
	  (((*fpnum) < 10000) && ((*fpnum) % 1000 == 0)) ||
	  (((*fpnum) < 100000) && ((*fpnum) % 10000 == 0)) ||
	  (((*fpnum) >= 100000) && ((*fpnum) % 100000 == 0)))
	{

	  unsigned frac;

	  if (debug)
	    fprintf(fp_stdout, "%s: ", cur_filename);
	  fprintf(fp_stdout, "Tp= %lu Tf=%lu ", (*fpnum), fcount);
	  if (!is_stdin)
	    {
	      location = ftell (stdin);
	      frac = location / filesize * 100;
	      fprintf(fp_stdout, "%u%%", frac);
	    }
	  /* print elapsed time */
	  {
	    double etime = elapsed (first_packet, last_packet);
	    fprintf(fp_stdout, " (%s)", elapsed2str (etime));
	  }
	  /* print number of opened flow */
	  {
	    fprintf(fp_stdout, " Nf(TCP)=%lu Nf(UDP)=%lu", tot_conn_TCP,
		     tot_conn_UDP);
	    fprintf(fp_stdout, " Ntrash=%lu", not_id_p);
	  }

	  /* carriage return (but not newline) */
	  fprintf(fp_stdout, "\r");
	}
      fflush(fp_stdout);
    }
#endif //TSTAT_RUNASLIB

  /* keep track of global times */
  if (ZERO_TIME (&first_packet))
   {
     first_packet = current_time;
   }
  last_packet = current_time;


  return 1;			/*finished ok */
}

void InitAfterFirstPacketReaded(char *filename, int file_count) {
  if ((con_cat == FALSE) || (file_count == 1)) {
    create_new_outfiles (filename, FALSE);
    if (crypto_conf==TRUE)
     {
       initialize_crypto(crypto_source,crypto_value,basenamedir);
     }
  }

  if (con_cat == FALSE)
    {
      // reset bitrate stats
      memset (&L3_bitrate, 0, sizeof (struct L3_bitrates));
      memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
      memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
      memset (&L7_udp_bitrate, 0, sizeof (struct L7_bitrates));

      tot_conn_TCP = 0;
      tot_conn_UDP = 0;
    }
}


//return 0: packet skipped
//return 1: packet analized
static int ProcessPacket(struct timeval *pckt_time, 
                         struct ip *pip,
                         void *plast,
                         int tlen, 
                         int phystype, 
                         u_long *fpnum, 
                         u_long *pcount, 
                         int file_count, 
                         char *filename, 
                         long int location,
			 int ip_direction)
{
    struct tcphdr *ptcp = NULL;
    int flow_stat_code;
    struct udphdr *pudp;
    int dir;
    struct stat finfo;
    int stat_error;
    static int stat_err_counter = 3;

    current_time = *pckt_time;

    //------------------ skip very close pkts 
    //  if (elapsed (last_packet, current_time) <= 0)
    //    continue;
    //  fprintf(fp_stderr,"%f \n", elapsed (last_packet, current_time));


    /* quick sanity check, better be an IPv4/v6 packet */
    if (!PIP_ISV4 (pip) && !PIP_ISV6 (pip))
    {
        static Bool warned = FALSE;

        if (!warned)
        {
            fprintf(fp_stderr, "Warning: saw at least one non-ip packet\n");
            warned = TRUE;
        }

        if (debug > 1)
            fprintf(fp_stderr,
                    "Skipping packet %lu, not an IPv4/v6 packet (version:%d)\n",
                    pnum, pip->ip_v);
        return 0;
    }

    /* If it's IP-over-IP, skip the external IP header */
    if (PIP_ISV4(pip) && (pip->ip_p == IPPROTO_IPIP || pip->ip_p == IPPROTO_IPV6))
     {
       pip = (struct ip *)((char *)pip+4*pip->ip_hl);
       if (!PIP_ISV4 (pip) && !PIP_ISV6 (pip))
        {
	  /* The same sanity check than above, but without warnings*/
          return 0;
        }
     }
     

    /* Statistics from IP HEADER */
    if (ip_header_stat
            (phystype, pip, fpnum, pcount, file_count, filename, location,
             tlen, plast, ip_direction) == 0)
        return 0;

    /* create a dump file at ip level */
    dump_ip(pip, plast);

    /* Statistics from LAYER 4 (TCP/UDP) HEADER */

     /* 
        IPv6 traffic is completely ignored in the L4 traffic stats, 
        if disabled from the command line.
     */
     if (PIP_ISV6(pip) && !ipv6_enabled)
       return 0;

    flow_stat_code = FLOW_STAT_NONE;  /* No flow (and dup) check done yet */

    if ( (ptcp = gettcp (pip, &plast)) != NULL)
     {
        ++tcp_packet_count;
        flow_stat_code = tcp_flow_stat (pip, ptcp, plast, &dir);
	if ( flow_stat_code!=FLOW_STAT_DUP && 
	     flow_stat_code!=FLOW_STAT_SHORT )
	   tcp_header_stat (ptcp, pip, plast);
     }	   
    else if (do_udp)
     {
        /* look for a UDP header */
        if ((pudp = getudp (pip, &plast)) != NULL)
	 { 
           flow_stat_code = udp_flow_stat (pip, pudp, plast);
	   if ( flow_stat_code!=FLOW_STAT_DUP && 
	        flow_stat_code!=FLOW_STAT_SHORT )
	      udp_header_stat (pudp, pip, plast);
	 }
     }

    if (flow_stat_code != FLOW_STAT_DUP)
     {
       if (!(PIP_ISV6 (pip)))
        {
          /* Collect IPv4 histograms only on not duplicated flows */
          ip_histo_stat(pip);
	} 
     }

    //if (flow_stat_code != FLOW_STAT_OK)
    //  return 0;

    //********************************************/
    //* check if the runtime config file is changed */
    //********************************************/
    
    force_create_new_outfiles = FALSE;    

    if (runtime_engine && 
        difftime(time(NULL), last_mtime_check) >= GLOBALS.Runtime_Config_Idle) 
    {
        last_mtime_check = time(NULL);

        // for sanity check we use a counter to check the max number
        // of stat fails. A fail may be related to the editor in case
        // of direct editing of the runtime config file
            // (Vim for example use a temporary file and replace this
            // with the original file when a change is made)
        stat_error = stat(runtime_conf_fname, &finfo);
        if (!stat_error) {
            stat_err_counter = 5;
            if (difftime(finfo.st_mtime, last_mtime)) {
                mtime_stable_counter = GLOBALS.Runtime_Mtime_Counter;
                last_mtime = finfo.st_mtime;
                if (debug) 
                    fprintf(fp_stdout, "Runtime configuration is changed\n");
            }
            // postpone reload runtime configuration until
            // the timestamp isn't changed for RUNTIME_MTIME_COUNTER times
            else if (mtime_stable_counter >= 0) {
                mtime_stable_counter--;
                // reload runtime configuration
                if (mtime_stable_counter == 0) {
                    if (debug)
                        fprintf(fp_stdout, "Reload runtime configuration...\n");
                    ini_read(runtime_conf_fname);
                    //dump_create_outdir(basename);
                }
            }
        }
        else if (stat_err_counter) {
            stat_err_counter--;
        }
        else {
            fprintf(fp_stderr, "err: '%s' - No such file\n", runtime_conf_fname);
            exit(1);
        }
    }

    //check if is need to flush histograms
    if (elapsed (last_time_step, current_time) > GLOBALS.Max_Time_Step)
    {
        flush_time_step();
    }

    if (force_create_new_outfiles == TRUE && first_packet_readed)
     {
       create_new_outfiles(NULL, FALSE);
       force_create_new_outfiles = FALSE;
     }

    /*
       however, if we do not have
       many packets, we'd wait forever
    // for efficiency, only allow a signal every 1000 packets       
    // (otherwise the system call overhead will kill us)            
    if (pnum % 1000 == 0)
    {
    sigset_t mask;

    sigemptyset (&mask);
    sigaddset (&mask, SIGINT);

    sigprocmask (SIG_UNBLOCK, &mask, NULL);
    // signal can happen EXACTLY HERE, when data structures are consistant 
    sigprocmask (SIG_BLOCK, &mask, NULL);
    }
    */
    return 1;
}

void ProcessFileCompleted(Bool last) {
    tstat_report report;
#ifndef TSTAT_RUNASLIB
    /* set ^C back to the default */
    /* (so we can kill the output if needed) */
    {
        sigset_t mask;

        sigemptyset (&mask);
        sigaddset (&mask, SIGINT);

        sigprocmask (SIG_UNBLOCK, &mask, NULL);
        signal (SIGINT, SIG_DFL);
    }
#endif

    /* statistics dumping modified for -c option*/

    if (con_cat == TRUE && last == FALSE)
    {
        flush_time_step();
    }
    else
    {
        {
            if (debug > 1)
                fprintf (fp_stdout, "DEB: writing stats for uncomplete traces... ");
            trace_done ();
            if (do_udp)
                udptrace_done ();

            flush_histo ();
            step = 0;


            /* dump engine */
            if (runtime_engine)
                dump_flush(TRUE);
            if (log_bitmask)
                close_all_logfiles();
        }
    }

#ifndef TSTAT_RUNASLIB
    get_stats_report(&report);
    //dump_internal_stats(&report, stdout);
    tstat_print_report(&report, fp_stdout);
#endif
}


// !!!fake function for normal use!!!
void tstat_new_logdir(char *filename, 
                      struct timeval *pckt_time) 
{
#ifdef TSTAT_RUNASLIB
    current_time = *pckt_time;
    cur_filename = filename;
    fpnum = 0;
    if (filename == NULL)
        filename = "TSTAT_RUNASLIB";
    InitAfterFirstPacketReaded(filename, 1);
#endif
}

// !!!fake function for normal use!!!
int tstat_next_pckt(struct timeval *pckt_time, 
                    void *ip_hdr, 
                    void *last_ip_byte,
                    int tlen,
		    int ip_direction) 
{
#ifdef TSTAT_RUNASLIB
    //use some fake parameter
    return ProcessPacket(pckt_time, (struct ip*)ip_hdr, last_ip_byte, tlen, 
                         PHYS_ETHER, &fpnum, &pcount, 1, cur_filename, 0,
			 ip_direction);
#else
    return 0;
#endif
}

// !!!fake function for normal use!!!
tstat_report * tstat_close(tstat_report *report) {
#ifdef TSTAT_RUNASLIB
    double etime;
    gettimeofday(&wallclock_temp, NULL);
    etime = elapsed (wallclock_start, wallclock_temp);

    //write stats to file
    ProcessFileCompleted(TRUE);
    rrdtool_close ();
    return get_stats_report(report);
#else
    return NULL;
#endif
}


#ifndef TSTAT_RUNASLIB
static void
ProcessFile (char *filename, Bool last)
{
  pread_f *ppread = NULL;
  int ret = 0;
  struct ip *pip;
  int phystype;
  void *phys;			/* physical transport header */
  int len;
  int tlen;
  void *plast;
  struct stat str_stat;
  long int location = 0;

  /* share the current file name */
  cur_filename = filename;
  fpnum = 0;
  first_packet_readed = FALSE;

  if (con_cat == FALSE)
    pcount = 0;


/*--------------------------------------------------- */
  /* open the input file as stdin, where libpcap reads it from */
  if (strcmp (filename, "stdin") != 0 && freopen (filename, "r", stdin) == NULL)
    {
      fprintf (fp_stderr, "%s %s\n", filename, strerror(errno));
      exit (-1);
    }

  /* see how big the file is */
  is_stdin = FALSE;
  filesize = 1;

  struct stat f_info;
  stat(filename, &f_info);
  if (strcmp (filename, "stdin") == 0 || S_ISFIFO(f_info.st_mode))
    {
      filesize = 1;
      is_stdin = TRUE;
    }
  else
    {
      if (stat (filename, &str_stat) != 0)
	{
	  fprintf (fp_stderr, "stat: %s\n", strerror(errno));
	  exit (EXIT_FAILURE);
	}
      else
	{
	  if (str_stat.st_mode == S_IFREG)
	    filesize = str_stat.st_size;
	}

    }

  if (live_flag == TRUE)
    {				/* live capture with libpcap */
      ppread = init_live_tcpdump (filename);
      if (debug > 0)
	fprintf(fp_stderr, "Capturing using libpcap\n");
    }
  else
    {
      /* check that the input file is a pcap/pcapng file */
      rewind (stdin);
      ppread = is_tcpdump (filename);

      /* if we haven't found a reader, then we can't continue */
      if (ppread == NULL)
	{
	  int count = 0;

	  fprintf(fp_stderr, "Unknown input file format\n");
	  Formats ();

	  /* check for ASCII, a common problem */
	  rewind (stdin);
	  while (TRUE)
	    {
	      int ch;
	      if ((ch = getchar ()) == EOF)
		break;
	      if (!isprint (ch))
		break;
	      if (++count >= 20)
		{
		  /* first 20 are all ASCII */
		  fprintf(fp_stderr,
			   "\nThis looks like an ASCII input file to me.\n");
		  exit (EXIT_FAILURE);
		}
	    }
	  exit (EXIT_FAILURE);
	}

      /* how big is it.... */
      if (debug > 0)
	{
	  /* print file size */
	  fprintf (fp_stdout, "Trace file size: %lu bytes\n", filesize);
	}
      location = 0;


      /* count the files */
      ++file_count;

    }

  // read the first packet, to get the timestamp of the trace 
  //
  // bugfix for not-matching output -- Fri Jul 14 18:51:06 CEST 2006
  do
    {
      ret = (*ppread) (&current_time, &len, &tlen, &phys, &phystype, &pip,
		       &plast);
    }
  while ((ret > 0)
	 && (current_time.tv_sec == 0 && current_time.tv_usec == 0));

  if (ret <= 0)
    {
      fprintf(fp_stderr,
	       "Not even a single packet read (check tcpdump filter)! "
               "Skipping current file.\n");
      return;
    }

  InitAfterFirstPacketReaded(filename, file_count);
  first_packet_readed = TRUE;

  /* read each packet */
  do
    {
        ProcessPacket(&current_time, pip, plast, tlen, phystype, &fpnum, &pcount, 
                      file_count, cur_filename, location, DEFAULT_NET);

    }
  while ((ret =
	  (*ppread) (&current_time, &len, &tlen, &phys, &phystype, &pip,
		     &plast)) > 0);

  ProcessFileCompleted(last);
}
#endif //TSTAT_RUNASLIB

void
QuitSig (int signum)
{
    tstat_report report;

  fprintf (fp_stdout, "%c\n\n", 7); /* BELL */
  fprintf (fp_stdout, "Terminating processing early on signal %d\n", signum);
  fprintf (fp_stdout, "Partial result after processing %lu packets:\n\n\n", pnum);

  if (debug > 1)
    fprintf (fp_stdout, "DEB: writing stats for uncomplete traces... ");
  trace_done ();
  if (do_udp)
    udptrace_done ();

  flush_histo ();

    get_stats_report(&report);
  //dump_internal_stats (&report, stderr);
  tstat_print_report(&report, fp_stderr);

  if (runtime_engine)
      dump_flush(TRUE);
  if (log_bitmask)
      close_all_logfiles();
  rrdtool_close ();
  exit (EXIT_FAILURE);
}


void
Usr1Sig (int signum)
{
    tstat_report report;

  fprintf (fp_stdout, "%c\n\n", 7);	/* BELL */
  fprintf (fp_stdout, "Got a signal USR1\n");
  get_stats_report(&report);
  //dump_internal_stats(&report, stderr);
  tstat_print_report(&report, fp_stderr);
}


tstat_report * get_stats_report(tstat_report *report) {
    double etime;
    gettimeofday (&wallclock_temp, NULL);
    etime = elapsed (wallclock_start, wallclock_temp);

    if (report != NULL) {
        report->pnum = pnum;
        report->fcount = fcount;
        report->f_TCP_count = f_TCP_count;
        report->f_UDP_count = f_UDP_count;
        report->f_RTP_count = f_RTP_count;
        report->f_RTCP_count = f_RTCP_count;
        report->f_RTP_tunneled_TCP_count = f_RTP_tunneled_TCP_count;
        report->search_count = search_count;
        report->tcp_packet_count = tcp_packet_count;
        report->udp_trace_count = udp_trace_count;
        report->not_id_p = not_id_p;
        report->avg_search = (double)search_count / (double)tcp_packet_count;
        report->tot_conn_TCP = tot_conn_TCP;
        report->tot_conn_UDP = tot_conn_UDP;
        report->num_tcp_pairs = num_tcp_pairs;
        report->wallclock = etime;
        report->pcktspersec = (int) ((double) pnum / (etime / 1000000));
        report->flowspersec = (int) ((double) fcount / (etime / 1000000));
    }
    return report;
}

extern int crypto_total_hit,crypto_total_insert,crypto_total_miss;
extern int crypto_total_hit_ipv6,crypto_total_insert_ipv6,crypto_total_miss_ipv6;

void
tstat_print_report (tstat_report *rep, FILE *wheref)
{
    fprintf(wheref, 
        "\n---\n"
        "Dumping internal status variables:\n"
        "---\n");
    fprintf(wheref, "total packet analized : %ld\n", rep->pnum);
    fprintf(wheref, "total flows analized : %lu\n", rep->fcount);
    fprintf(wheref, "total TCP flows analized : %lu\n", rep->f_TCP_count);
    fprintf(wheref, "total UDP flows analized : %lu\n", rep->f_UDP_count);
    fprintf(wheref, "total RTP flows analized : %lu\n", rep->f_RTP_count);
    fprintf(wheref, "total RTCP flows analized : %lu\n", rep->f_RTCP_count);
    fprintf(wheref, "total tunneled RTP flows analized : %lu\n", 
            rep->f_RTP_tunneled_TCP_count); /*topix */
    fprintf(wheref, "total iteration spent in the hash search routine : %d\n",
            rep->search_count);
    fprintf(wheref, "total analyzed TCP packet: %ld \n", rep->tcp_packet_count);
    fprintf(wheref, "total analyzed UDP packet: %ld \n", rep->udp_trace_count);

    fprintf(wheref, "total trash TCP packet: %ld \n", rep->not_id_p);
    if (tcp_packet_count != 0)
        fprintf(wheref, "average TCP search length: %f\n", rep->avg_search);
    fprintf(wheref, "Current opened flows: TCP = %ld UDP = %ld\n",
            rep->tot_conn_TCP, rep->tot_conn_UDP);
    fprintf(wheref, "Current flow vector index: %d (%d)\n", 
            rep->num_tcp_pairs, GLOBALS.Max_TCP_Pairs);
    fprintf(wheref, "elapsed wallclock time: %s\n", elapsed2str(rep->wallclock));
    fprintf(wheref, "%d pkts/sec analyzed\n", rep->pcktspersec);
    fprintf(wheref, "%d flows/sec analyzed\n", rep->flowspersec);

    if (crypto_conf==TRUE)
     {
       fprintf(wheref, "Hash Insert: %d Hit: %d Miss: %d\n", crypto_total_insert,crypto_total_hit,crypto_total_miss);
       fprintf(wheref, "Hash IPv6 Insert: %d Hit: %d Miss: %d\n", crypto_total_insert_ipv6,crypto_total_hit_ipv6,crypto_total_miss_ipv6);
     }
    /* print out libpcap live capture stats */
    if (live_flag == TRUE)
        tcpdump_cleanup (wheref);
}

void *
MallocZ (int nbytes)
{
  char *ptr;

  ptr = malloc (nbytes);
  if (ptr == NULL)
    {
      fprintf (fp_stderr, "Malloc failed, fatal: %s\n", strerror(errno));
      fprintf(fp_stderr, 
        "when memory allocation fails, it's either because:\n"
        "1) You're out of swap space, talk to your local "
        "sysadmin about making more\n"
        "(look for system commands 'swap' or 'swapon' for quick fixes)\n"
        "2) The amount of memory that your OS gives each process "
        "is too little\n"
        "That's a system configuration issue that you'll need to discuss\n"
        "with the system administrator\n");
      exit (EXIT_FAILURE);
    }

  memset (ptr, 0, nbytes);	/* BZERO */

  return (ptr);
}


/* convert a buffer to an argc,argv[] pair 
void
StringToArgv (char *buf, int *pargc, char ***pargv)
{
  char **argv;
  int nargs = 0;

  // discard the original string, use a copy 
  buf = strdup (buf);

  // (very pessimistically) make the argv array 
  argv = malloc (sizeof (char *) * ((strlen (buf) / 2) + 1));

  // skip leading blanks 
  while ((*buf != '\00') && (isspace ((int) *buf)))
    {
      if (debug > 10)
	fprintf (fp_stdout, "skipping isspace('%c')\n", *buf);
      ++buf;
    }

  // break into args 
  for (nargs = 1; *buf != '\00'; ++nargs)
    {
      char *stringend;
      argv[nargs] = buf;

      // search for separator 
      while ((*buf != '\00') && (!isspace ((int) *buf)))
	{
	  if (debug > 10)
	    fprintf (fp_stdout, "'%c' (%d) is NOT a space\n", *buf, (int) *buf);
	  ++buf;
	}
      stringend = buf;

      // skip spaces 
      while ((*buf != '\00') && (isspace ((int) *buf)))
	{
	  if (debug > 10)
	    fprintf (fp_stdout, "'%c' (%d) IS a space\n", *buf, (int) *buf);
	  ++buf;
	}

    // terminate the previous string 
      *stringend = '\00';	

      if (debug)
	fprintf (fp_stdout, "  argv[%d] = '%s'\n", nargs, argv[nargs]);
    }

  *pargc = nargs;
  *pargv = argv;
}
*/


char **
ArgsFromFile(char *fname, int *pargc) {
    FILE *f;
    char buffer[1024];
    char *word;
    int i;
    char **argv, **tmpargv;

    f = fopen(fname, "r");    
    if (f == NULL) {
//        Help();
        fprintf(fp_stderr, "No '%s' file. Try 'tstat -h' for more information.\n", fname);
        exit(1);
    }

    //init argc/argv
    *pargc = 1;
    argv = malloc(sizeof(char *));
    argv[0] = strdup("tstat");
    
    //debug message
    //fprintf(fp_stdout, "Reading options from %s\n", fname);

    while(fgets(buffer, 1024, f)) {
        word = strtok(buffer, " \t\n");
        while(word != NULL) {
            //skip comments and void lines
            if (word[0] == '#' || word[0] == '\0')
                break;
           
            //increase cmdline buffer size
            tmpargv = malloc(sizeof(char *) * (*pargc + 1));
            for (i = 0; i < *pargc; i++) {
                tmpargv[i] = argv[i];
            }
            free(argv);
            argv = tmpargv;

            //add new parameter
            i = strlen(word);
            if (word[i] == '\n')
                word[i] = '\0';
            argv[*pargc] = strdup(word);
            *pargc = *pargc + 1;

            //debug message
            //fprintf(fp_stdout, "new option/param: %s\n", word);

            word = strtok(NULL, " \t\n");
        }
    }

    //debug message
    //fprintf(fp_stdout, "Configuration file analized\n");
    return argv;
}


static void
CheckArguments (int *pargc, char *argv[])
{
    char **tmpargv, *fname;
    int i, tot_args;

    fp_stdout = stdout;
    fp_stderr = stderr;
    if (*pargc == 1)
    {
#ifdef TSTAT_RUNASLIB
        fname = argv[0];
#else
        fname = "tstat.conf";
#endif
        tmpargv = ArgsFromFile (fname, pargc);
        tot_args = *pargc;
        ParseArgs (pargc, tmpargv);
        //debug messages
        if (debug >= 2) {
            fprintf(fp_stdout, "config: reading options from %s\n", fname);
            for (i = 0; i < tot_args; i++) {
                fprintf(fp_stdout, "config: added option/param: %s\n", tmpargv[i]);
            }
            fprintf(fp_stdout, "config: reading options completed\n");
        }
    }
    else
    {
        ParseArgs (pargc, argv);
    }

    /* make sure we found the files */
    /*
    if (filenames == NULL && 
        live_flag == FALSE)
    {
        BadArg (NULL, "must specify at least one file name\n");
    }
    */
    if (net_conf == FALSE && eth_conf == FALSE) {
	    internal_net_mask[0] = 0;
        inet_aton ("0.0.0.0", &(internal_net_list[0]));
        tot_internal_nets = 1;
        if (debug)
        {
	    struct in_addr mask2;
	    mask2.s_addr = internal_net_mask[0];
            fprintf (fp_stdout, "Adding: %s as internal net ",
                    inet_ntoa (internal_net_list[0]));
            fprintf (fp_stdout, "with mask %s (%u)\n", 
                    inet_ntoa (mask2),
                    internal_net_mask[0]);
        }
        fprintf(fp_stdout, 
            ANSI_BOLD "Warning:" ANSI_RESET " -N option not specified.\n"
            "         All subnets are assumed to be internal\n");
    }
    if (crypto_conf == FALSE) {
        tot_crypto_nets = 0;
	tot_white_nets = 0;
        tot_crypto_netsv6 = 0;
	tot_white_netsv6 = 0;
    }
    /*-----------------------------------------------------------*/
    /* RRDtools                                                */
    /* make sure we found the files */
    if ((rrdset_path && !rrdset_conf) || (!rrdset_path && rrdset_conf))
        BadArg (NULL,
                "You MUST specify both the configuration file (-R) AND the database path (-r))\n");

    if (crypto_conf == FALSE && key_modes_set>0 )
     {
       fprintf(fp_stdout, 
               ANSI_BOLD "Warning:" ANSI_RESET " One encryption key option has been specified but no encrypted\n"
               "         networks have been defined with the -Y option. Encryption is disabled\n");
     }
     
    if (crypto_conf == FALSE && white_conf == TRUE )
     {
       fprintf(fp_stdout, 
               ANSI_BOLD "Warning:" ANSI_RESET " A set of whitelisted networks has been provided but no encrypted\n"
               "         networks have been defined with the -Y option.\n");
     }

    if (crypto_conf == FALSE && enc_string_set == TRUE )
     {
       fprintf(fp_stdout, 
               ANSI_BOLD "Warning:" ANSI_RESET " The encryption of all relevant hostnames has been requested, but\n"
               "         no encrypted networks have been defined with the -Y option. The option is ignored\n");
       enc_string_set = FALSE;
     }
}

/* command line options */
#define TSTAT_OPTS "li:E:f:r:R:6QXF:A:G:N:M:Y:W:H:s:T:z:gdhtucSLvw0"

static void
ParseArgs (int *pargc, char *argv[])
{
  struct stat finfo;
  char *tmpstring;

  int option_index;
  int c;
  static int has_keyfile;
  static int has_keybase64;
  static int has_keyvalue;
  static int has_enc;
  static struct option long_options[] = {
    /* {option_name,has_arg(0=none,1=recquired,2=optional),flag,return_value} */
    /* see man getopt for details                                             */
    {"keyfile", required_argument, &has_keyfile, 1},
    {"keybase64", required_argument, &has_keybase64, 1},
    {"keyvalue", required_argument, &has_keyvalue, 1},
    {"enc", no_argument, &has_enc, 1},
    {0, 0, 0, 0}
  };

  option_index = 0;
  opterr = 0;
  optind = 1;
  //check '-z' option immediatelly so we can redirect all the messages
  while(1) {
    c = getopt_long (*pargc, argv,
		     TSTAT_OPTS, long_options, &option_index);
    if (c == -1)
        break;
    if (c == 'z') {
      fp_stdout = fopen(optarg, "w");
      if (!fp_stdout) {
          fprintf(stderr, "Error creating %s\n", optarg);
          exit(1);
      }
      fp_stderr = fp_stdout;
      break;
    } 
  }

  //Note: RESET argument so we can parse again command line arguments!!!
  option_index = 0;
  optind = 1;
  opterr = 0;
  //check if we need to override globals
  while(1) {
    c = getopt_long (*pargc, argv,
		     TSTAT_OPTS, long_options, &option_index);
    if (c == -1)
        break;
    if (c == 'G') {
	  /* -G file for global parameters */
	  
	  tmpstring = strdup (optarg);
	  if (!LoadGlobals (tmpstring))
	    {
	      fprintf (fp_stderr, 
            "Error while loading Global parameters configuration\n"
	        "Wrong or missing %s\n", tmpstring);
	      exit (1);
	    }
      break;
    } 
  }

  /* This is the moment we can actually allocate Global arrays */
  InitGlobalArrays();
  
  //Note: RESET argument so we can parse again command line arguments!!!
  option_index = 0;
  optind = 1;
  opterr = 0;
  /* parse the args */
  while (1)
    {
      c = getopt_long (*pargc, argv,
		     TSTAT_OPTS, long_options, &option_index);

      if (c == -1) {
	    break;
      }

      if (debug > 2)
	fprintf (fp_stdout, "ParseArgs[%d]=%s\n", optind, argv[optind]);

      switch (c)
	{
	case 'M':
	  /* -M file */
	  tmpstring = strdup (optarg);
	  if (!LoadInternalEth (tmpstring))
	    {
	      fprintf (fp_stderr, 
            "Error while loading MAC addresses configuration\n"
	        "Wrong or missing %s\n", tmpstring);
	      exit (1);
	    }
	  eth_conf = TRUE;
	  if (eth_conf && net_conf)
	   {
         fprintf(fp_stdout, 
            ANSI_BOLD "Warning:" ANSI_RESET " Both -M and -N options specified.\n"
            "         Ethernet filter is used and -N addresses are ineffective\n");
	   }
	  break;
	case 'N':
	  /* -N file */
	  tmpstring = strdup (optarg);
	  if (!LoadInternalNets (tmpstring))
	    {
	      fprintf (fp_stderr, 
            "Error while loading NET addresses configuration\n"
	        "Wrong or missing %s\n", tmpstring);
	      exit (1);
	    }
	  net_conf = TRUE;
	  if (eth_conf && net_conf)
	   {
         fprintf(fp_stdout, 
            ANSI_BOLD "Warning:" ANSI_RESET " Both -M and -N options specified.\n"
            "         Ethernet filter is used and -N addresses are ineffective\n");
	   }
         if (tot_internal_nets == 0)
	  {
	    internal_net_mask[0] = 0;
            inet_aton ("0.0.0.0", &(internal_net_list[0]));
            tot_internal_nets = 1;
            if (debug)
             {
	       struct in_addr mask2;
	       mask2.s_addr = internal_net_mask[0];
               fprintf (fp_stdout, "Adding: %s as internal net ",
                    inet_ntoa (internal_net_list[0]));
               fprintf (fp_stdout, "with mask %s (%u)\n", 
                    inet_ntoa (mask2),
                    internal_net_mask[0]);
             }
            fprintf(fp_stdout, 
               ANSI_BOLD "Warning:" ANSI_RESET " -N option contains no IPv4 network.\n"
               "         All IPv4 subnets are assumed to be internal\n");
	  }
         if (tot_internal_netsv6==0)
	  {
        internal_net_maskv6[0] = 0;
        inet_pton(AF_INET6,"::",&(internal_net_listv6[0]));
        tot_internal_netsv6=1;
        if (debug)
            {
            char s[INET6_ADDRSTRLEN];
            inet_ntop (AF_INET6,&(internal_net_listv6[0]),s,INET6_ADDRSTRLEN);
            fprintf (fp_stdout, "Adding: %s as %s ",s,"::");
            fprintf (fp_stdout, "with mask %u\n",
                    internal_net_maskv6[0]);
            }        
            fprintf(fp_stdout, 
               ANSI_BOLD "Warning:" ANSI_RESET " -N option contains no IPv6 network.\n"
               "         All IPv6 subnets are assumed to be internal\n");
	  }
	  break;
	case 'Y':
	  /* -Y file */
	  tmpstring = strdup (optarg);
	  if (!LoadCryptoNets (tmpstring))
	    {
	      fprintf (fp_stderr, 
            "Error while loading configuration\n"
	        "Wrong or missing %s\n", tmpstring);
	      exit (1);
	    }
	  crypto_conf = TRUE;
	  if (crypto_source==CPKEY_UNDEF) 
	    { // If no key option ()--keyfile --keyvalue --keybase64)
	      // has already been parsed, set the key to random, 
	      // otherwise maintain the values set by the option
	     crypto_source = CPKEY_RANDOM;
	     crypto_value = NULL;
	    }
	  break;
	case 'W':
	  /* -W file */
	  tmpstring = strdup (optarg);
	  if (!LoadWhiteNets (tmpstring))
	    {
	      fprintf (fp_stderr, 
            "Error while loading configuration\n"
	        "Wrong or missing %s\n", tmpstring);
	      exit (1);
	    }
	  white_conf = TRUE;
	  break;
	case 'A':		/* Enable anonymization with the mask indicated */
	   {
	     char *endptr;
	     errno = 0;
	     tmpstring = strdup (optarg);
	     long long obf_mask = strtoll(tmpstring,&endptr,0);
	     if (*endptr=='\0' && errno==0)
	      {
		/* Mask must be converted to network order */
	         ip_obfuscate_mask = htonl((unsigned int)(obf_mask & 0x00000000ffffffff));
 	        // if (debug > 0)
	         fprintf (fp_stdout, "Anonymization mask set to 0x%08x\n", ntohl(ip_obfuscate_mask));
	      }
	     else
	      { 
	        fprintf (fp_stdout, "Invalid value %s(0x%08x) for the anonymization mask - Using default value 0x%08x\n",
		         tmpstring,(unsigned int)obf_mask,ntohl(ip_obfuscate_mask));
	      }
	    }
	  break;
	case '6':
	  ipv6_enabled = FALSE;
	  fprintf (fp_stdout, ANSI_BOLD "IPv6 traffic ignored" ANSI_RESET "\n");
	  break;
	case 'X':
	  dns_enabled = FALSE;
	  fprintf (fp_stdout, ANSI_BOLD "DNS engine disabled" ANSI_RESET "\n");
	  break;
	case 'Q':
	  report_dnscache = TRUE;
	  fprintf (fp_stdout, ANSI_BOLD "DNS engine cache wrap-around report enabled" ANSI_RESET "\n");
	  break;
	case 'F':
	  {
	    dns_namefilter_file = strdup (optarg);
        dns_namefilter_specified = TRUE;
	  }
	  break;
	case 'd':
	  ++debug;
	  break;
	case 'g':
	case 'H':
	case 'S':
	  /* removed text histograms: accepted and ignored for compatibility
	     with older configuration files */
	  fprintf (fp_stderr, "Warning: option -%c is obsolete and has been ignored\n", c);
	  break;
	case 'h':
	  Usage ();
	  break;
	case 'l':
	  live_flag = TRUE;
	  break;
	case 'i':		/* choose the live capture interface card */
	  /* -ieth0 */
	  dev = strdup (optarg);
	  if (debug > 1)
	    fprintf (fp_stdout, "Capturing device set to %s\n", dev);
	  break;
	case 'E':		/* choose the snaplen for the live capture */
	   {
	     int slen = strtol(optarg,NULL,10);
	     if (slen>0 && slen<65536)
	      {
	        snaplen = slen;
 	        if (debug > 1)
	          fprintf (fp_stdout, "SnapLen set to %d\n", snaplen);
	      }
	     else
	      { 
	        fprintf (fp_stdout, "Invalid value %d for SnapLen - Using default value %d\n",slen,snaplen);
	      }
	    }
	  break;
	case 't':
	  printticks = TRUE;
	  break;
	case 'u':
	  do_udp = FALSE;
	  break;
	case 'c':
	  con_cat = TRUE;
	  break;
	case 's':
	  /* -sdir */
	  basenamedir = strdup (optarg);
	  basedirspecified = TRUE;
	  if (debug > 1)
	    fprintf (fp_stdout, "basenamedir set to %s\n", basenamedir);
	  break;
	case 'f':		/* pcap filter file */
	  /* -ffilter_file */
	  filter_filename = strdup (optarg);
	  filter_specified = TRUE;
	  break;
		/*-----------------------------------------------------------*/
	  /* RRDtools                                                  */
	case 'r':
	  {
	    /* -Rfile */
	    char *rrdpath = strdup (optarg);
	    struct stat fbuf;
	    if ((stat (rrdpath, &fbuf) == 0) && S_ISDIR (fbuf.st_mode))
	      {
		if (debug)
		  fprintf (fp_stdout,
			   "RRDTool database path <%s> exists\n", rrdpath);
	      }
	    else
	      {
		char command[1000];
		sprintf(command, "mkdir -p %s ", rrdpath);
		system(command);
		//mkdir (rrdpath, 0775);
		if (debug)
		  fprintf (fp_stdout,
			   "RRDTool database path <%s> created\n", rrdpath);
	      }
	    rrdtool_set_path (rrdpath);
	    rrdset_path = 1;
	  }
	  break;

	case 'R':
	  {
	    /* -Rfile */
	    char *rrdconf = strdup (optarg);
	    struct stat fbuf;
	    if (stat (rrdconf, &fbuf) == 0)
	      {
		if (debug)
		  fprintf (fp_stdout,
			   "RRDTool configuration file <%s> found (delayed parsing)\n",
			   rrdconf);
		rrdtool_set_conf (rrdconf);
	      }
	    else
	      {
		fprintf (fp_stderr, "err: Could not open %s\n", rrdconf);
		exit (1);
	      }
	    rrdset_conf = 1;
	  }
	  break;
		/*-----------------------------------------------------------*/

    case 'T':
      sprintf(runtime_conf_fname, "%s", optarg);
      if (stat(runtime_conf_fname, &finfo)) {
          fprintf(fp_stderr, "err: Could not open %s\n", runtime_conf_fname);
          exit(1);
      }
      else if (S_ISDIR(finfo.st_mode)) {
          fprintf(fp_stderr, "err: %s is a directory\n", runtime_conf_fname);
          exit(1);
      }
      runtime_engine = TRUE;
      last_mtime = finfo.st_mtime;
      last_mtime_check = time(NULL);
      mtime_stable_counter = -1;
      break;


	case 'L':
	  log_bitmask = 0;
	  break;
	case '0':
	  strict_privacy = TRUE;
	  break;
	case 'v':
	  Version ();
	  exit (EXIT_SUCCESS);
	  break;
	case 'w':
	  warn_printtrunc = TRUE;
	  warn_printbadmbz = TRUE;
	  warn_printbadcsum = TRUE;
	  warn_printbad_syn_fin_seq = TRUE;
	  warn_ooo = TRUE;
	  break;
/* process long options */
	case 1:
	  switch (option_index)
	    {

	    default:
	      fprintf (fp_stderr, "\n Error in parsing long opt %d\n", option_index);
	      break;
	    }
	  break;

    case 0: /* long options with flags */
        key_modes_set = has_keyfile + has_keybase64 + has_keyvalue;
	enc_string_set = (has_enc==1?TRUE:FALSE);
	
	if (key_modes_set > 1)
	 {
	   fprintf (fp_stderr, 
            "Error: Only one encryption key option (--keyvalue, --keyfile, --keybase64)\n"
            "       can be used\n");
	      exit (1);
	 }

        if (has_keyfile==1 && optarg)
	 { /* --keyfile */
	   crypto_value = strdup (optarg);
	   crypto_source = CPKEY_FILE;
	 }
        else if (has_keybase64==1 && optarg)
	 { /* --keyfile */
	   crypto_value = strdup (optarg);
	   crypto_source = CPKEY_FILE64;
	 }
	else if (has_keyvalue==1 && optarg)
	 {
	   crypto_value = strdup (optarg);
	   crypto_source = CPKEY_CLI;
	 }
        break;
    case 'z': //skip because we already readed it
        break;
    case 'G': //skip because we already readed it
        break;
	default:
      Help();
      fprintf (fp_stderr, "option -%c not valid or missing option argument\n", c);
	  exit (EXIT_FAILURE);
	}
    }

  *pargc -= optind;
  if (*pargc)
    filenames = &argv[optind];
}

int
ParseNetFile (FILE *fp, char *qualifier, int max_entries, 
              struct in_addr *CLASS_net_list,
	      struct in6_addr *CLASS_net_listv6,
              int *CLASS_net_mask,
	      int *CLASS_net_mask_sizev6,
              int *tot_CLASS_nets,
	      int *tot_CLASS_netsv6) {
    char *line, *ip_string, *mask_string, *err;
    int i,j,k,len;
    int is_ipv4;
    long int mask_bits;
    unsigned int full_local_mask;
    struct in_addr mask2;
    char s[INET6_ADDRSTRLEN];

    (*tot_CLASS_nets) = 0;
    (*tot_CLASS_netsv6) = 0;
    i = 0; // File line
    j = 0; // Index for IPv4
    k = 0; // Index for IPv6
    while (1) {
        line = readline(fp, 1, 1);
        if (!line)
            break;

        len = strlen(line);
        if (line[len - 1] == '\n')
            line[len - 1] = '\0';
        ip_string = line;

        if (j == max_entries) {
            fprintf (fp_stderr, "Maximum number of %s IPv4 hosts/networks (%d) exceeded\n", qualifier, max_entries);
            return 0;
        }
        
        if (k == max_entries) {
            fprintf (fp_stderr, "Maximum number of %s IPv6 hosts/networks (%d) exceeded\n", qualifier, max_entries);
            return 0;
        }

        is_ipv4 = 0;
        //single line format
        if (strchr(ip_string,'/'))
        {
            ip_string = strtok(ip_string,"/");
            mask_string = strtok(NULL,"/");

            if (!mask_string) {
                fprintf(fp_stderr, "Missing ip or network mask in %s config n.%d\n", qualifier, (i+1));
                return 0;
            }
            
            if (strchr(ip_string,':')) 
	     {  // IPv6 Address
                if (!inet_pton (AF_INET6,ip_string, &(CLASS_net_listv6[k]))) 
		  {
	            fprintf(fp_stderr, "Invalid ip address in %s config n.%d\n", qualifier, (i+1));
                    return 0;
                  }
	        is_ipv4 = 0;
	     }
	    else
	     {  // IPv4 Address
                if (!inet_pton (AF_INET,ip_string, &(CLASS_net_list[j])))
		 {
                   fprintf(fp_stderr, "Invalid ip address in %s config n.%d\n", qualifier, (i+1));
                   return 0;
	         }
	        is_ipv4 = 1;
             }

            //network mask as a single number
            if (!strchr(mask_string,'.'))
            { 
                err = NULL;
                mask_bits = strtol(mask_string, &err, 10);
		if (is_ipv4==1)
		 {
                   if (*err || mask_bits < 0 || mask_bits > 32) {
                      fprintf(fp_stderr, "Invalid network mask in %s config n.%d\n", qualifier, (i+1));
                      return 0;
		    }
                   else if (mask_bits==0)
	            {
                      fprintf(fp_stderr, ANSI_BOLD "Warning:" ANSI_RESET " IPv4 mask set to 0 bits in %s config n.%d\n\tAny IPv4 address will be considered internal\n",
		         qualifier, (i+1));
		      CLASS_net_list[j].s_addr = 0; 
	            }
	            
                   if (CLASS_net_list[j].s_addr == 0)
                     full_local_mask = 0;
                   else
                     full_local_mask = 0xffffffff << (32 - mask_bits);

                   sprintf(s,"%d.%d.%d.%d",
                      full_local_mask >> 24,
                      (full_local_mask >> 16)  & 0x00ff,
                      (full_local_mask >> 8 ) & 0x0000ff,
                      full_local_mask & 0xff);
                   // inet_aton (s, &(CLASS_net_mask2[j]));
                   CLASS_net_mask[j] = inet_addr(s);
	           CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
		 }
		else
		 {
                   if (*err || mask_bits < 0 || mask_bits > 128) {
                     fprintf(fp_stderr, "Invalid network mask in %s config n.%d\n", qualifier, (i+1));
                     return 0;
                     }
                   else if (mask_bits>64 && mask_bits!=128)
	            {
                      fprintf(fp_stderr, ANSI_BOLD "Warning:" ANSI_RESET " IPv6 mask should not exceed 64 bits in %s config n.%d\n", qualifier, (i+1));
	              // mask_bits=64;
	            }
                   else if (mask_bits==0)
	            {
                      fprintf(fp_stderr, ANSI_BOLD "Warning:" ANSI_RESET " IPv6 mask set to 0 bits in %s config n.%d\n\tAny IPv6 address will be considered internal\n",
		         qualifier, (i+1));
	            }

                   CLASS_net_mask_sizev6[k] = mask_bits;
		  }
            }
            //mask in dotted format
            else if (is_ipv4==1)
            {
                if (!inet_aton (mask_string, &mask2)) {
                    fprintf(fp_stderr, "Invalid IPv4 network mask in %s config n.%d\n", qualifier, (i+1));
                    return 0;
                }
                CLASS_net_mask[j] = inet_addr (mask_string);
	        CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
            }
            else
	    {
               fprintf(fp_stderr, "Invalid IPv6 network mask in %s config n.%d\n", qualifier, (i+1));
               return 0;
	    }
        }
        //old format
        else
        {
            if (!inet_aton (ip_string, &(CLASS_net_list[j]))) {
                fprintf(fp_stderr, "Invalid IPv4 address in %s config n.%d\n", qualifier, (i+1));
                return 0;
            }

            mask_string = readline(fp, 1, 1);
            if (!mask_string){
                fprintf(fp_stderr, "Missing IPv4 network mask in %s config n.%d\n", qualifier, (i+1));
                return 0;
            }

            len = strlen(mask_string);
            if (mask_string[len - 1] == '\n')
                mask_string[len - 1] = '\0';
            if (!inet_aton (mask_string, &mask2)) {
                fprintf(fp_stderr, "Invalid IPv4 network mask in %s config n.%d\n", qualifier, (i+1));
                return 0;
            }
            CLASS_net_mask[j] = inet_addr (mask_string);
	    CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
            is_ipv4 = 1;
        }
       if (debug)
        {
	  if (is_ipv4==1)
	   {
	    mask2.s_addr = CLASS_net_mask[j];
            fprintf (fp_stdout, "Adding: %s as %s ",
                    inet_ntoa (CLASS_net_list[j]),qualifier);
            fprintf (fp_stdout, "with mask %s (%u)\n", 
                    inet_ntoa (mask2),
                    CLASS_net_mask[j]);
	   }
	   else
	   {
	    inet_ntop (AF_INET6,&(CLASS_net_listv6[k]),s,INET6_ADDRSTRLEN);
            fprintf (fp_stdout, "Adding: %s as %s ",s,qualifier);
            fprintf (fp_stdout, "with mask %u\n",
                    CLASS_net_mask_sizev6[k]);
	   }
        }
        
        if (is_ipv4==1)
 	 {
           (*tot_CLASS_nets)++;
	   j++;
	 }
	 else
	 {
           (*tot_CLASS_netsv6)++;
	   k++;
	 }
        i++;
    }
    return 1;
}

int
LoadInternalNets (char *file) {
    FILE *fp;
    int retval;

    fp = fopen(file, "r");
    if (!fp) {
        fprintf(fp_stderr, "Unable to open file '%s'\n", file);
        return 0;
    }


    retval = ParseNetFile(fp,"internal",GLOBALS.Max_Internal_Hosts,
			     internal_net_list,internal_net_listv6,
			     internal_net_mask,internal_net_maskv6,
			     &tot_internal_nets,&tot_internal_netsv6);
			     
//			     printf("Read %d IPv4 networks and %d IPv6 networks\n",tot_internal_nets,
//				    tot_internal_netsv6);
    fclose(fp);
    
    return retval;
}

int
LoadCryptoNets (char *file) {
    FILE *fp;
    int retval;

    fp = fopen(file, "r");
    if (!fp) {
        fprintf(fp_stderr, "Unable to open file '%s'\n", file);
        return 0;
    }

    retval = ParseNetFile(fp,"crypto",GLOBALS.Max_Crypto_Hosts,
			     crypto_net_list,crypto_net_listv6,
			     crypto_net_mask,crypto_net_maskv6,
			     &tot_crypto_nets,&tot_crypto_netsv6);
   
    fclose(fp);
    
    return retval;
}

int
LoadWhiteNets (char *file) {
    FILE *fp;
    int retval;

    fp = fopen(file, "r");
    if (!fp) {
        fprintf(fp_stderr, "Unable to open file '%s'\n", file);
        return 0;
    }

    retval = ParseNetFile(fp,"whitelisted",GLOBALS.Max_White_Hosts,
			     white_net_list,white_net_listv6,
			     white_net_mask,white_net_maskv6,
			     &tot_white_nets,&tot_white_netsv6);
   
    fclose(fp);
    
    return retval;
}


int 
LoadInternalEth (char *file) {
    FILE *fp;
    char *line;
    struct ether_addr *mac_addr;
    int i, len;

    fp = fopen(file, "r");
    if (!fp) {
        fprintf(fp_stderr, "Unable to open file '%s' when parsing the Ethernet filters\n", file);
        return 0;
    }

    i = 0;
    while (1) {
        line = readline(fp, 1, 1);
        if (!line)
            break;

        len = strlen(line);
        if ( line[len - 1] == '\n' )
            line[len - 1] = '\0';

		if ( i == GLOBALS.Max_Internal_Ethers )	{
            fprintf (fp_stderr, "Maximum number of internal Ethernet (%d) exceeded\n", GLOBALS.Max_Internal_Ethers);
            return 0;
        }

        mac_addr = ether_aton(line);
        if (mac_addr!=NULL)
         {
	        memcpy(mac_filter.addr[i], mac_addr, 6);
	     }
	    else
	     {
            fprintf(fp_stderr, "Wrong address format in Ethernet filter n.%d\n", (i+1));
            return 0;
	     }
        
        if (debug>1)
        {
            fprintf (fp_stdout, "Adding: %s as internal net ",
                    ether_ntoa ((const struct ether_addr *)mac_filter.addr[i]));
        }
        i++;
    }
    mac_filter.tot_internal_eth = i;    
    return 1;
}

/* 
 * Check if the IP adx is included in the internal nets
 */

Bool
internal_ip (struct in_addr adx)
{
  int i;

  //fprintf(fp_stdout, "Checking %s \n",inet_ntoa(adx));
  for (i = 0; i < tot_internal_nets; i++)
    {
      //fprintf(fp_stdout, " Against: %s \n",inet_ntoa(internal_net_list[i]));
      if ((adx.s_addr & internal_net_mask[i]) == internal_net_list[i].s_addr)
	{
	  //fprintf(fp_stdout, "Internal: %s\n",inet_ntoa(adx));
	  return 1;
	}
    }
  //fprintf(fp_stdout, "External: %s\n",inet_ntoa(adx));
  return 0;
}

/* 
 * Check if the IP adx is included in the crypto nets
 */

Bool
crypto_ip (struct in_addr adx)
{
  int i,j;

  //fprintf(fp_stdout, "Checking %s \n",inet_ntoa(adx));
  for (i = 0; i < tot_crypto_nets; i++)
    {
      //fprintf(fp_stdout, " Against: %s \n",inet_ntoa(crypto_net_list[i]));
      if ((adx.s_addr & crypto_net_mask[i]) == crypto_net_list[i].s_addr)
	{
	  //fprintf(fp_stdout, "Crypto: %s\n",inet_ntoa(adx));
          for (j = 0; j < tot_white_nets; j++)
           {
             //fprintf(fp_stdout, " Against: %s \n",inet_ntoa(white_net_list[j]));
             if ((adx.s_addr & white_net_mask[j]) == white_net_list[j].s_addr)
	      {
	        //fprintf(fp_stdout, "White: %s\n",inet_ntoa(adx));
	        return 0;
	      }
           }
           /* Is encrypted only if it */
	  return 1;
	}
    }
  //fprintf(fp_stdout, "Not-crypto: %s\n",inet_ntoa(adx));
  return 0;
}

Bool
internal_eth (uint8_t *eth_addr, eth_filter *filter)
{
  int i;

  if (debug>1) 
    fprintf(fp_stdout, "Checking %s \n", ether_ntoa((const struct ether_addr *)eth_addr));
  for (i = 0; i < filter->tot_internal_eth; i++)
    {
      if (debug>1) 
        fprintf(fp_stdout, " Against: %s \n",ether_ntoa((const struct ether_addr *)filter->addr[i]));
      if (memcmp(eth_addr, filter->addr[i], 6) == 0)
       {
	     if (debug>1) 
	       fprintf(fp_stdout, "\t\tInternal: %s\n",ether_ntoa((const struct ether_addr *)eth_addr));
	     return 1;
       }
    }
  if (debug>1) 
    fprintf(fp_stdout, "\t\tExternal: %s\n",ether_ntoa((const struct ether_addr *)eth_addr));
  return 0;
}

/****************************************************
 * AF: these functions are for parsing runtime.conf
 ****************************************************/

/* Logs of removed features, accepted and ignored for compatibility
   with older configuration files */
static char *obsolete_log_params[] = {
  "log_skype_complete", "log_chat_complete", "log_chat_messages",
  "log_video_complete", "histo_engine",
  NULL
};

/* this function is to apply the same logic to different log files
 * Note: 'log_type' is one of the LOG_XXX values in tstat.h
 */
static long old_log_bitmask;
void log_parse_ini_arg_log_bitmask(FILE *fp, int log_type, char * log_name, int enabled) {
    if (enabled && !LOG_IS_ENABLED(log_type)) {
        fprintf(fp_stdout, "[%s] Enabling %s\n", Timestamp(), log_name);
        log_bitmask |= log_type;
    }
    else if (!enabled && LOG_IS_ENABLED(log_type)) {
        fprintf(fp_stdout, "[%s] Disabling %s\n", Timestamp(), log_name);
        log_bitmask &= ~log_type;
        // since we are stopping the collection of stats, we force a flush 
        if (fp != NULL) {
            fflush(fp);
        }
    }
}

void log_parse_start_section(void) {
  extern int globals_set;

  if (globals_set!=0)
   {
     fprintf(fp_stderr,"ini reader: [logs] section only valid in the runtime configuration context\n");
     exit(1);
   } 
  
    old_log_bitmask = log_bitmask;
}

void log_parse_end_section(void) {
    if (old_log_bitmask && !log_bitmask) {
        fprintf(fp_stdout, "[%s] All logs disabled\n", Timestamp());
    }
    if (old_log_bitmask != log_bitmask && first_packet_readed) {
       // create_new_outfiles(NULL, TRUE);
       force_create_new_outfiles = TRUE;
    }
    old_log_bitmask = log_bitmask;
}

void log_parse_ini_arg(char *param_name, param_value enabled) {
    if (enabled.type!=INTEGER && enabled.value.ivalue != 0 && enabled.value.ivalue != 1) {
        fprintf(fp_stderr, "ini reader: expected 0|1 value near '%s'\n", param_name);
        exit(1);
    }

    //rrd engine
    if (strcmp(param_name, "rrd_engine") == 0) {
        //stdout messages
        if (!rrd_engine && enabled.value.ivalue)
            fprintf(fp_stdout, "[%s] Enabling rrd engine logs\n", Timestamp());
        else if (rrd_engine && !(enabled.value.ivalue))
            fprintf(fp_stdout, "[%s] Disabling rrd engine logs\n", Timestamp());
        rrd_engine = enabled.value.ivalue;
    }

    else if (strcmp(param_name, "log_tcp_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_logc, LOG_TCP_COMPLETE, "log_tcp_complete", enabled.value.ivalue);
    }
    else if (strcmp(param_name, "log_tcp_nocomplete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_lognc, LOG_TCP_NOCOMPLETE, "log_tcp_nocomplete", enabled.value.ivalue);
    }
    else if (strcmp(param_name, "log_udp_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_udp_logc, LOG_UDP_COMPLETE, "log_udp_complete", enabled.value.ivalue);
    }
    else if (strcmp(param_name, "log_mm_complete") == 0) {
       log_parse_ini_arg_log_bitmask(fp_rtp_logc, LOG_MM_COMPLETE, "log_mm_complete", enabled.value.ivalue);
    }
    else if (strcmp(param_name, "log_http_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_http_logc, LOG_HTTP_COMPLETE, "log_http_complete", enabled.value.ivalue);
    }
    else if (strcmp(param_name, "log_tcp_periodic") == 0) {
        log_parse_ini_arg_log_bitmask(fp_periodic_logc, LOG_TCP_PERIODIC, "log_tcp_periodic", enabled.value.ivalue);
    }
    else if (strcmp(param_name, "log_udp_periodic") == 0) {
        log_parse_ini_arg_log_bitmask(fp_periodic_udp_logc, LOG_UDP_PERIODIC, "log_udp_periodic", enabled.value.ivalue);
    }
    else if (strcmp(param_name, "log_dns_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_dns_logc, LOG_DNS_COMPLETE, "log_dns_complete", enabled.value.ivalue);
    }
    else if (!is_obsolete_param(param_name, obsolete_log_params)) {
        fprintf(fp_stderr, "ini reader: '%s' - unknown keyword\n", param_name);
        exit(1);
    }
}

/* Called at the end of every time step (GLOBALS.Max_Time_Step) */
void flush_time_step(void) {

    flush_histo ();

    step++;
#ifndef TSTAT_RUNASLIB
    /* In case we are processing live streams, create a new dir every
       DIRS steps */
    if (step >= GLOBALS.Dirs && is_stdin)
#else
    /* is_stdin is not set when running as libtstat */
    if (step >= GLOBALS.Dirs)
#endif
      {
        create_new_outfiles (NULL, FALSE);
        step = 0;
      }

    last_time_step = current_time;
    // reset bitrate stats 
    memset (&L3_bitrate, 0, sizeof (struct L3_bitrates));
    memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
    memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
    memset (&L7_udp_bitrate, 0, sizeof (struct L7_bitrates));
}
