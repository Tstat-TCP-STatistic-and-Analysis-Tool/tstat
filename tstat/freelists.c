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

/* 
** Memory management with freelist instead of malloc and free.
**
*/


/*
**  Function  : void *MMmalloc(size_t size, const char * function_name)
**  Return    : the pointer to the memory of the new allocated block
**  Remarks   : MMmalloc() allocates size bytes and returns a pointer to the
**              allocated memory.  The memory is cleared.
**              If an error occours, an error is printed, including the
**              function name of the calling function.
*/
void *
MMmalloc (size_t size, const char *f_name)
{
  void *temp_pointer;
  if ((temp_pointer = malloc (size)) == NULL)
    {
      /* If problems arise from the memory allocation, an error message is    */
      /* printed before exiting the program execution.                        */
      fprintf (fp_stderr, 
        "\nError:  Memory allocation error in Tstat function %s\n", f_name);
      exit (1);
    }
  memset (temp_pointer, 0, size);
  return temp_pointer;
}

/* Garbage collector for the tcp_pair structs
* Two pointer are used (top and last).
* Alloc and release from last, while top is used to not loose the list ...
*/

static struct tp_list_elem *top_tp_flist = NULL;	/* Pointer to the top of      */
					     /* the 'tplist' free list.    */
static struct tp_list_elem *last_tp_flist = NULL;	/* Pointer to the last used   */
					     /* element list.              */

tcp_pair *
tp_alloc (void)
{
  tcp_pair *ptp_temp;

  if ((last_tp_flist == NULL) || (last_tp_flist->ptp == NULL))
    {				/* The LinkList stack is empty.         */
      /* fprintf (fp_stdout, "FList empty, top == last == NULL\n"); */
      ptp_temp = (tcp_pair *) MMmalloc (sizeof (tcp_pair), "tplist_alloc");
      ptp_temp->c2s.ss = (seqspace *) MallocZ (sizeof (seqspace));
      ptp_temp->s2c.ss = (seqspace *) MallocZ (sizeof (seqspace));

      return ptp_temp;
    }
  else
    {				/* The 'tplist' stack is not empty.   */
      ptp_temp = last_tp_flist->ptp;
      last_tp_flist->ptp = NULL;
      if (last_tp_flist->next != NULL)
	last_tp_flist = last_tp_flist->next;
      return ptp_temp;
    }
}

void
tp_release (tcp_pair * released_tcp_pair)
{
  struct tp_list_elem *new_tplist_elem;
  seqspace *sstemp1, *sstemp2;

  if (released_tcp_pair->ssl_client_subject!=NULL)
   {
     free(released_tcp_pair->ssl_client_subject);
     released_tcp_pair->ssl_client_subject=NULL;
   }

  if (released_tcp_pair->ssl_server_subject!=NULL)
   {
     free(released_tcp_pair->ssl_server_subject);
     released_tcp_pair->ssl_server_subject=NULL;
   }

  if (released_tcp_pair->ssl_client_tls_version!=NULL)
   {
     free(released_tcp_pair->ssl_client_tls_version);
     released_tcp_pair->ssl_client_tls_version=NULL;
   }

  if (released_tcp_pair->ssl_server_tls_version!=NULL)
   {
     free(released_tcp_pair->ssl_server_tls_version);
     released_tcp_pair->ssl_server_tls_version=NULL;
   }
   
  if (released_tcp_pair->ssl_client_hello_buffer!=NULL)
   {
     free(released_tcp_pair->ssl_client_hello_buffer);
     released_tcp_pair->ssl_client_hello_buffer=NULL;
   }

  if (released_tcp_pair->dns_name!=NULL)
   {
     free(released_tcp_pair->dns_name);
     released_tcp_pair->dns_name=NULL;
   }
  
  if (released_tcp_pair->http_hostname!=NULL)
   {
     free(released_tcp_pair->http_hostname);
     released_tcp_pair->http_hostname=NULL;
   }

  memset (released_tcp_pair->c2s.ss, 0, sizeof (seqspace));
  memset (released_tcp_pair->s2c.ss, 0, sizeof (seqspace));
  sstemp1 = released_tcp_pair->c2s.ss;
  sstemp2 = released_tcp_pair->s2c.ss;

  memset (released_tcp_pair, 0, sizeof (tcp_pair));

  released_tcp_pair->c2s.ss = sstemp1;
  released_tcp_pair->s2c.ss = sstemp2;

  if ((last_tp_flist == NULL)
      || ((last_tp_flist->ptp != NULL) && (last_tp_flist->prev == NULL)))
    {

      new_tplist_elem =
	(struct tp_list_elem *) MMmalloc (sizeof (struct tp_list_elem),
					  "tplist_release");
      new_tplist_elem->ptp = released_tcp_pair;
      new_tplist_elem->prev = NULL;
      new_tplist_elem->next = top_tp_flist;
      if (new_tplist_elem->next != NULL)
	new_tplist_elem->next->prev = new_tplist_elem;
      top_tp_flist = new_tplist_elem;
      last_tp_flist = new_tplist_elem;
    }
  else
    {
      if (last_tp_flist->ptp == NULL)
	new_tplist_elem = last_tp_flist;
      else
	new_tplist_elem = last_tp_flist->prev;
      new_tplist_elem->ptp = released_tcp_pair;
      last_tp_flist = new_tplist_elem;
    }
}


/* garbage collector for the segment list */

static segment *segment_flist = NULL;	/* Pointer to the top of      */
					/* the 'segment' free list.  */
segment *
segment_alloc (void)
{
  segment *pseg;

  if (segment_flist == NULL)
    {
      pseg = (segment *) MallocZ (sizeof (segment));
    }
  else
    {
      pseg = segment_flist;
      segment_flist = segment_flist->next;
    }
  pseg->next = NULL;
  return pseg;
}

void
segment_release (segment * rel_segment)
{
  memset (rel_segment, 0, sizeof (segment));
  rel_segment->next = segment_flist;
  segment_flist = rel_segment;
}


/* garbage collector for the Quadrant */

static quadrant *quadrant_flist = NULL;	/* Pointer to the top of      */
					/* the 'quadrant' free list.  */

quadrant *
quadrant_alloc (void)
{
  quadrant *pquad;

  if (quadrant_flist == NULL)
    {
      pquad = (quadrant *) MallocZ (sizeof (quadrant));
    }
  else
    {
      pquad = quadrant_flist;
      quadrant_flist = quadrant_flist->next;
    }
  pquad->next = NULL;
  return pquad;
}

void
quadrant_release (quadrant * rel_quadrant)
{
  memset (rel_quadrant, 0, sizeof (quadrant));
  rel_quadrant->next = quadrant_flist;
  quadrant_flist = rel_quadrant;
}


/* garbage collector for the ptp_snap list */

static ptp_snap *top_ptph_flist = NULL;	/* Pointer to the top of      */
					/* the 'ptp_snap' free list.    */
ptp_snap *
ptph_alloc (void)
{
  struct ptp_snap *new_ptph;


  if (top_ptph_flist == NULL)
    {
      new_ptph = (ptp_snap *) MMmalloc (sizeof (ptp_snap), "ptph_alloc");
    }
  else
    {
      new_ptph = top_ptph_flist;
      top_ptph_flist = top_ptph_flist->next;
    }
  new_ptph->next = NULL;
  return (new_ptph);
}

void
ptph_release (ptp_snap * rel_ptph)
{
  memset (rel_ptph, 0, sizeof (ptp_snap));
  rel_ptph->next = top_ptph_flist;
  top_ptph_flist = rel_ptph;
}


/* garbage collection of udp_pair */

static udp_pair *udp_pair_flist = NULL;	/* Pointer to the top of      */
					/* the 'udp_pair' free list.  */

udp_pair *
utp_alloc (void)
{
  udp_pair *pud;

  if (udp_pair_flist == NULL)
    {
      pud = (udp_pair *) MallocZ (sizeof (udp_pair));
    }
  else
    {
      pud = udp_pair_flist;
      udp_pair_flist = udp_pair_flist->next;
    }
  pud->next = NULL;

  return (pud);
}

void
utp_release (udp_pair * rel_udp_pair)
{

  if (rel_udp_pair->dns_name!=NULL)
   {
     free(rel_udp_pair->dns_name);
     rel_udp_pair->dns_name=NULL;
   }

  if (rel_udp_pair->quic_sni_name!=NULL)
   {
     free(rel_udp_pair->quic_sni_name);
     rel_udp_pair->quic_sni_name=NULL;
   }

  if (rel_udp_pair->quic_ua_string!=NULL)
   {
     free(rel_udp_pair->quic_ua_string);
     rel_udp_pair->quic_ua_string=NULL;
   }
   
  if (rel_udp_pair->quic_client_hello!=NULL)
   {
     free(rel_udp_pair->quic_client_hello);
     rel_udp_pair->quic_client_hello=NULL;
   }
   
  while (rel_udp_pair->c2s.flow_ptr.rtp_ptr!=NULL)
   {
     rtp *this = rel_udp_pair->c2s.flow_ptr.rtp_ptr;
     rel_udp_pair->c2s.flow_ptr.rtp_ptr = rel_udp_pair->c2s.flow_ptr.rtp_ptr->next;
     free(this);
   }
   
  while (rel_udp_pair->c2s.flow_ptr.rtcp_ptr!=NULL)
   {
     rtcp *this = rel_udp_pair->c2s.flow_ptr.rtcp_ptr;
     rel_udp_pair->c2s.flow_ptr.rtcp_ptr = rel_udp_pair->c2s.flow_ptr.rtcp_ptr->next;
     free(this);
   }
   
  while (rel_udp_pair->s2c.flow_ptr.rtp_ptr!=NULL)
   {
     rtp *this = rel_udp_pair->s2c.flow_ptr.rtp_ptr;
     rel_udp_pair->s2c.flow_ptr.rtp_ptr = rel_udp_pair->s2c.flow_ptr.rtp_ptr->next;
     free(this);
   }

  while (rel_udp_pair->s2c.flow_ptr.rtcp_ptr!=NULL)
   {
     rtcp *this = rel_udp_pair->s2c.flow_ptr.rtcp_ptr;
     rel_udp_pair->s2c.flow_ptr.rtcp_ptr = rel_udp_pair->s2c.flow_ptr.rtcp_ptr->next;
     free(this);
   }

  memset (rel_udp_pair, 0, sizeof (udp_pair));	/* reset all the fields */
  rel_udp_pair->next = udp_pair_flist;
  udp_pair_flist = rel_udp_pair;
}
