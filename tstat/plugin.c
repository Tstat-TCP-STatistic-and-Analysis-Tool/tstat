/*
 *
 * Copyright (c) 2001
 *      Politecnico di Torino.  All rights reserved.
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
 
 INSTRUCTIONS:
 to add any new ABC protocol analyzer, you need to do a couple of things:
 	*) include the header ABC.h which exports 
	   getABC and ABC_flow_analyzer
	*) call proto_register()  in proto_init(), such as:
  	
		proto_register(PROTOCOL_UDP, "ABC", "Meaning of ABC", 
		  	(void *) getrtp, 
			(void *) rtp_flow_stat);
		
	   note that the the ABC analyzer can be registered as 
	   ABC/TCP, ABC/UDP or ABC/both depending on the PROTOCOL_XXX flag
 
 
*/
#include "tstat.h"


/* increase the threshold to get rid of proto dbg msg */
#define PROTO_DEBUG_LEVEL 2
#define PROTO_DEBUG (PROTO_DEBUG_LEVEL>0 && debug>=PROTO_DEBUG_LEVEL)
extern int debug;
extern Bool runtime_engine;
extern Bool dns_enabled;

/* chain of protocol analyzer */
struct proto *proto_list_head;
static int proto_num = 0;

/* any new protocol analyzer module MUST export these two functions:  */
void *dummy_init(void);
void *getdummy (void *pproto, int tproto, void *plast, void *phdr);

//===================================================================================
//  register new protocol analyzer engines
//-----------------------------------------------------------------------------------

int
proto_init ()
{
  if (PROTO_DEBUG)
    fprintf (fp_stderr, "proto: init() begins\n");

  /* note that the order in which you register the protocol IS RELEVANT */
  /* the registration order is LIFO, i.e., the last plugin that is */
  /* registered is the first that is then called */

  if (runtime_engine == TRUE) {
      proto_register(PROTOCOL_BOTH, "DUMP", "Dump file accordingly DPI",
        (void *) getdummy,
        (void *) dump_flow_stat,
        (void *) dummy_init,
        NULL);
  }

  proto_register (PROTOCOL_TCP, "HTTP", "HTTP Requests",
		  (void *) gethttp,
		  (void *) http_flow_stat,
		  (void *) http_init,
		  (void *) make_http_conn_stats);


  proto_register (PROTOCOL_UDP, "LOG_DNS", "Log DNS generator",
		  (void *) check_dns,
		  (void *) dns_flow_stat,
          NULL,
          NULL);

   if (dns_enabled)
    {
      proto_register (PROTOCOL_UDP, "DNS", "DNS Cache Processor",
		  (void *) check_dns_response,
		  (void *) dns_process_response,
		  (void *) dns_cache_init,
          (void *) dns_cache_status);
    }

  proto_register (PROTOCOL_TCP, "TCPL7", "Layer 7 TCP Protocols",
		  (void *) gettcpL7,
		  (void *) tcpL7_flow_stat,
		  (void *) tcpL7_init,
          (void *) make_tcpL7_conn_stats);

  proto_register (PROTOCOL_UDP, "RTP", "Real Time Protocol",
		  (void *) getrtp,
		  (void *) rtp_flow_stat,
          NULL,
          (void *) make_rtp_conn_stats);

  proto_register (PROTOCOL_UDP, "UDPL7", "Layer 7 UDP Protocols",
		  (void *) getudpL7,
		  (void *) udpL7_flow_stat,
		  NULL,
		  (void *) make_udpL7_conn_stats);


  /* 
     example to add a new protocol analyzer:
     proto_register(PROTOCOL_BOTH, "Dummy", "Dummy -- Example protocol analyzer", 
     (void *) getdummy, 
     (void *) dummy_init,
     (void *) dummy_flow_stat,
     (void *) make_dummy_conn_stats
     );
   */

  if (PROTO_DEBUG)
    fprintf (fp_stderr, "proto: init() done\n");
  return 1;
}

//===================================================================================
// register a protocol analyzer for a given
//-----------------------------------------------------------------------------------

int
proto_register (int tproto, char *name, char *descr, void *(*check) (),
		void *(*analyze) (), void *(*init) (), void *(*stat) ())
{
  if (PROTO_DEBUG)
    fprintf (fp_stderr,
	     "proto: registering protocol[%d] (%s,%s) over %s with function (%p,%p,%p,%p)\n",
	     ++proto_num, name, descr, proto_description (tproto), check,
	     analyze, init, stat);

  struct proto *pproto =
    (struct proto *) MMmalloc (sizeof (struct proto), "proto_register");
  pproto->next = proto_list_head;
  proto_list_head = pproto;

/*
   The  strdup()  function  returns  a  pointer to a new string which is a
   duplicate of the string s.  Memory for the new string is obtained  with
   malloc(3), and can be freed with free(3).
*/

  pproto->name = strdup (name);
  pproto->descr = strdup (descr);
  pproto->check = check;
  pproto->analyze = analyze;
  pproto->init = init;
  pproto->stat = stat;
  pproto->tproto = tproto;

  // calling initialization routine
  if (init != NULL)
    pproto->init ();
  return 1;
}


//===================================================================================
// analyze protocols of the upper layers (5 and above);
//-----------------------------------------------------------------------------------

void
proto_analyzer (struct ip *pip, void *pproto, int tproto, void *pdir, int dir,
		void *plast)
{
  if (PROTO_DEBUG)
    fprintf (fp_stderr, "proto: analyze() begins\n");

  struct proto *protocol = proto_list_head;
  void *phdr = NULL;
  void *ret = NULL;

  while (protocol != NULL)
    {
      if ((tproto == protocol->tproto) || (protocol->tproto == PROTOCOL_BOTH))
	{
	  if (PROTO_DEBUG)
	    fprintf (fp_stderr, "%ld: testing %s frame for %sness ...",
		     pnum, proto_description (tproto), protocol->name);

	  /* phdr sometimes fail, so we use the ptr returned by the function */
	  ret = (void *) (protocol->check (pproto, tproto, phdr, plast));

	  if (ret != NULL)
	    {
	      if (PROTO_DEBUG)
		fprintf (fp_stderr, "yup!\n");

	      protocol->analyze (pip, pproto, tproto, pdir, dir, ret, plast);
	    }
	  else
	    {
	      if (PROTO_DEBUG)
		fprintf (fp_stderr, "nope!\n");
	    }
	}
      else
	{
	  if (PROTO_DEBUG)
	    fprintf (fp_stderr, "skipping %s who expect %s while frame is %s\n",
		     protocol->name, proto_description (protocol->tproto),
		     proto_description (tproto));
	}

      protocol = protocol->next;
    }

  if (PROTO_DEBUG)
    fprintf (fp_stderr, "proto: analyze() ends\n");
}

void
make_proto_stat (void *thisflow, int tproto)
{
  if (PROTO_DEBUG)
    fprintf (fp_stderr, "proto: stat() begins\n");

  struct proto *protocol = proto_list_head;
  while (protocol != NULL)
    {
      if ((tproto == protocol->tproto) || (protocol->tproto == PROTOCOL_BOTH))
	{
	  if (PROTO_DEBUG)
	    fprintf (fp_stderr, "making %s stat for %s ...",
		     proto_description (tproto), protocol->name);

	  /* call the real function */
	   if(protocol->stat != NULL)
              protocol->stat (thisflow, tproto);
	}
      else
	{
	  if (PROTO_DEBUG)
	    fprintf (fp_stderr, "skipping stat for %s (expeting %s, got %s)\n",
		     protocol->name, proto_description (protocol->tproto),
		     proto_description (tproto));
	}
      protocol = protocol->next;
    }

  if (PROTO_DEBUG)
    fprintf (fp_stderr, "proto: stat() ends\n");
}


//===================================================================================
// dummy protocol analyzer example 
//-----------------------------------------------------------------------------------

void * dummy_init(void) {
    return (void *)NULL;
}

void *
getdummy (void *pproto, int tproto, void *plast, void *p)
{
  // this func should return the header of the
  // upper-layer protocol (i.e., ``dummy''in this 
  // case) that is intended to be analyzed.
  p = (void *) pproto;
  return p;
}

