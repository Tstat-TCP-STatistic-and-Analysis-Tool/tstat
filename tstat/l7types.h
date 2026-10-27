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
/* define the FLOW number for the histo hit */
#define L4_FLOW_TCP             0
#define L4_FLOW_UDP             1
#define L4_FLOW_TOT             2

/* L7 flow types used as index in the histograms (and RRD files).
   The values of removed protocols are not reused */
#define L7_FLOW_HTTP            0
#define L7_FLOW_RTP             1
#define L7_FLOW_RTCP            2
#define L7_FLOW_RTSP            4
#define L7_FLOW_SMTP            25
#define L7_FLOW_POP3            26
#define L7_FLOW_IMAP            27
#define L7_FLOW_SSL             33
#define L7_FLOW_DNS             36
#define L7_FLOW_SSH             37
#define L7_FLOW_RTMP            38
#define L7_FLOW_DTLS            44
#define L7_FLOW_QUIC            45
#define L7_FLOW_MTURN           47

#define L7_FLOW_UNKNOWN         49    /* Unknown is set to the largest ID */
#define L7_FLOW_TOT             50
