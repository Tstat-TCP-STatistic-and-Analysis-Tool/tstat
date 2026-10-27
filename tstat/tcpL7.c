/*
 *
 * Copyright (c) 2001-2008
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

#include <regex.h>

int map_flow_type(tcp_pair *thisflow);

extern struct L4_bitrates L4_bitrate;
extern struct L7_bitrates L7_bitrate;
extern struct L7_bitrates L7_udp_bitrate;

extern int verify_long_method(u_int32_t , void *);


regex_t re_ssl_subject,re_ssl_clean;
char cname[80];
char tls_version_list[80];

void
tcpL7_init ()
{
   regcomp(&re_ssl_subject,"[A-Za-z0-9]+\\.[A-Za-z0-9]{2,24}\\.?$",REG_EXTENDED);
   regcomp(&re_ssl_clean,"[^[:cntrl:][:space:]]+",REG_EXTENDED);

}

void *
gettcpL7 (struct udphdr *pudp, int tproto, void *pdir, void *plast)
{
  /* just pass the complete packet and let the tcpL7_flow_stat decide */

  return (void *) pudp;
}

int ssl_parse_npnalpn_extension(char *base, int idx, int ii, int data_limit, int ext_len, Bool isNPN) {
    int res = 0;
    int iii = 0;
    int safety = 20;
    while ( iii < ext_len && (idx + ii + iii) < data_limit && safety > 0 ) 
     {
        unsigned char npnproto_len = (unsigned char)base[idx + ii + iii];

	safety--; /* Not nice, but we need to avoid an infinite loop */
	
	//if (npnproto_len < 0)
	// {
	//   fprintf(fp_stderr,"Warning: failure parsing TLS header (npnproto_len = %d)\n",npnproto_len);
	//   break;
	// }
	 
        if (npnproto_len == 0)
	 {

            res = (isNPN) ? NPN_EMPTY : ALPN_EMPTY;
            break;
         }

        iii += 1;
        if (idx + ii + iii + npnproto_len > data_limit) 
            break;
        // check if NPN carries the string "spdy/"
        else if (base[idx + ii + iii]  == 0x73 &&
                base[idx + ii + iii+1] == 0x70 &&
                base[idx + ii + iii+2] == 0x64 &&
                base[idx + ii + iii+3] == 0x79 &&
                base[idx + ii + iii+4] == 0x2F) 
          {
           res |= (isNPN) ? NPN_SPDY : ALPN_SPDY;
          }
        // check if NPN carries the string is (exactly) "h2" or starts with "h2-"
        else if (base[idx + ii + iii]  == 0x68 &&
                base[idx + ii + iii+1] == 0x32 &&
                ( base[idx + ii + iii-1] == 0x02 || base[idx + ii + iii+2] == 0x2D) ) 
          {
            res |= (isNPN) ? NPN_H2 : ALPN_H2;
          }
        else if (base[idx + ii + iii]  == 0x68 &&
                base[idx + ii + iii+1] == 0x74 &&
                base[idx + ii + iii+2] == 0x74 &&
                base[idx + ii + iii+3] == 0x70 &&
                base[idx + ii + iii+4] == 0x2F)
          {
            res |= (isNPN) ? NPN_HTTP : ALPN_HTTP;
          }
        iii += npnproto_len;
     }
     
    if (safety == 0)
     {
       fprintf(fp_stderr,"Warning: failure parsing TLS header (too many iterations)\n");
     }
     
    return res;
}

Bool ssl_client_parse_tls(tcp_pair *ptp, void *pdata, int payload_len, int data_length)
{
  char *base;
  int idx,all_ext_len,ext_type,ext_len,name_len,data_limit;
  int ii,j,next;
  int tls_message_version;
  
  base = (char *)pdata;

  // Lenght of the Hello Message, including 5 bytes for the TLS header
  int message_length = 5 + ntohs(*(tt_uint16 *)(base+3));
      
  // printf("Data = %d Message = %d Payload = %d\n",data_length,message_length,payload_len);

  /* TLS version in the message */
  tls_message_version = ntohs(*(tt_uint16 *)(base+9));

  sprintf(tls_version_list,"%04x",tls_message_version);
  if (ptp->ssl_client_tls_version==NULL) 
	   ptp->ssl_client_tls_version = strdup(tls_version_list);

      // printf("C <- %s\n",ptp->ssl_client_tls_version);
     
      // All tests must be limited to the Hello Message, so
      // we define the minimum between the Message Lenght and the 
      // actual data available in the segment
      
  data_limit = min(data_length,message_length);
      
      // Index of the SessionID lenght field
  idx = 43;              

      // Add session length = 1st byte of cipher suite section
      if (idx > data_limit) 
        return TRUE;
      
      idx += 1 + base[idx];

      // Add length of cipher suite section = 1st byte of compression section
      if (idx + 2 > data_limit) 
        return TRUE;
      
      idx += 2 + ntohs(*(tt_uint16 *)(base+idx)); 

      // Add length of compression section = 1st byte of extensions section
      if (idx > data_limit)
        return TRUE;
      idx += 1 + base[idx];

      // Full extensions section length
      if (idx + 2 > data_limit) 
        return TRUE;

      all_ext_len = ntohs(*(tt_uint16 *)(base+idx));
      if (all_ext_len < 0)
        return TRUE;
      idx += 2; 
      
      // 1st byte of the 1st extension
      ii = 0;   // pointer within the current extension
      next = 0;
      while (ii < all_ext_len && idx+ii < data_limit)
       {
          // extract extension type
          if (idx+ii+2 > data_limit) 
            return TRUE;
          ext_type = ntohs(*(tt_uint16 *)(base+idx+ii));
          ii += 2;

          // extract extension length
          if (idx + ii + 2 > data_limit) 
            return TRUE;
          ext_len = ntohs(*(tt_uint16 *)(base + idx + ii));
          if (ext_len < 0)
            return TRUE;
          ii += 2;

          switch (ext_type)
           {
              // SNI (Server Name Indication)
              case 0x0000:
                  // extension length
                  if (idx+ii+2 > data_limit) 
                    return TRUE;
                  next = ii + ext_len;

                  // skip up to the 1st byte of "Server Name"
                  ii += 3;
                  if (idx+ii+2 > data_limit) 
                    return TRUE;
                  name_len = ntohs(*(tt_uint16 *)(base+idx+ii));
                  ii += 2;

                  // copy server name
                  if (idx+ii > data_limit) 
                    return TRUE;
                  for (j=0; j < name_len && j < 79 && idx+ii+j < data_limit; j++)
                   {
                      cname[j]=base[idx+ii+j];
                   }
                  cname[j]='\0';

                  // crosscheck that subject has a reasonable syntax
                  if (regexec(&re_ssl_subject,cname, (size_t) 0, NULL, 0)==0)
                   {
		      if (regexec(&re_ssl_clean,cname, (size_t) 0, NULL, 0)==0)
                         ptp->ssl_client_subject = strdup(cname);
                   }

                  ii = next;
                  break;

              // NPN (Next Protocol Negotiation)
              // the assumption in place is that if the client employ NPN, then it is for SPDY
              case 0x3374:
                  if (ext_len == 0) 
		   {
                      ptp->ssl_client_npnalpn |= NPN_EMPTY;
                   }
                  else 
		   {
                      ptp->ssl_client_npnalpn |= ssl_parse_npnalpn_extension(base, idx, ii, data_limit, ext_len, TRUE);
                   }

                  ii += ext_len;
                  break;

              case 0x0010:
                  if (ext_len == 0) 
		   {
                      ptp->ssl_client_npnalpn |= ALPN_EMPTY;
                   }
                  else 
		   {
                      if (idx + ii + 2 > data_limit) 
                        return TRUE;
                      // extract the protocols length
                      ext_len = ntohs(*(tt_uint16 *)(base+idx+ii));
                      if (ext_len < 0)
                        return TRUE;
                      ii += 2; 
                      ptp->ssl_client_npnalpn |= ssl_parse_npnalpn_extension(base, idx, ii, data_limit, ext_len, FALSE);
                   }

                  ii += ext_len;
                  break;

              case 0x002b: /* Supported Versions (TLS Version Negotiation)*/
	          if (ext_len != 0) 
		   {
                     int versions_length;
                     int j;
	             int tls_version_item;
	             static char scratch[8];
		     
                     if (idx + ii + 2 >= data_limit) 
                       return TRUE;
		     
                     versions_length = *(base+idx+ii);
	       
	             if (versions_length < 0)
		       return TRUE;
	       
	             if (idx + ii + 1 + versions_length >= data_limit) 
                       return TRUE;

	             strcpy(tls_version_list,"");
                     for (j=0;j<versions_length;j+=2)
                      {
		        tls_version_item = ntohs(*(tt_uint16 *)(base+idx+ii+1+j));
		        if (j==0)
		           sprintf(tls_version_list,"%04x",tls_version_item);
		        else
		         {
		           sprintf(scratch,",%04x",tls_version_item);
			   if (strlen(tls_version_list)<74)
		             strcat(tls_version_list,scratch);
		         }
                      }
                
                    /* Must overwrite the message version*/ 
                     if (ptp->ssl_client_tls_version!=NULL) 
		       free(ptp->ssl_client_tls_version);
	             ptp->ssl_client_tls_version = strdup(tls_version_list);
                    // printf("C -> %s\n",ptp->ssl_client_tls_version);
                   }

                  ii += ext_len;
                  break;

              case 0x0029: /* Client PSK extension present */
                  ptp->ssl_client_PSK = TRUE;
                  ii += ext_len;
                  break;

              case 0x002a: /* Client Early Data extension present */
                  ptp->ssl_client_early_data = TRUE;
                  ii += ext_len;
                  break;

              default:
                  ii += ext_len;
                  break;
           }
       }

      return TRUE;  // the return value is never used
   }

Bool ssl_client_check(tcp_pair *ptp, void *pdata, int payload_len, int data_length)
{
  int record_length;
  char *base;
  
  if (  *(char *)pdata == 0x16 &&  //fixed value
      *(char *)(pdata + 1) == 0x03 && 
    ( *(char *)(pdata + 2) >= 0x00 && *(char *)(pdata + 2) <= 0x03 ) && 
    ( *(char *)(pdata + 3) >= 0x00 && *(char *)(pdata + 3) <= 0x39 ) && // SSL/TLS max record size is 16kB
      *(char *)(pdata + 5) == 0x01 // Client Hello message type
     )
   { 
     /* Match SSL 3 - TLS 1.x Handshake Client HELLO */
      ptp->state = SSL_HANDSHAKE;

      base = (char *)pdata;

      // Lenght of the Hello Message, including 5 bytes for the TLS header
      int message_length = 5 + ntohs(*(tt_uint16 *)(base+3));
      
      // printf("Data = %d Message = %d Payload = %d\n",data_length,message_length,payload_len);

      if (message_length > data_length)
        {
          // Store the payload and postpone the parsing
          if (ptp->ssl_client_hello_buffer==NULL)
           {
              ptp->ssl_client_hello_buffer = (char *)malloc(message_length*sizeof(char));
              if (ptp->ssl_client_hello_buffer!=NULL)
               memcpy(ptp->ssl_client_hello_buffer,pdata,data_length);
               ptp->ssl_client_hello_offset=data_length;
               ptp->ssl_client_hello_message_len = message_length;
           }
        }
      else
        {
          // We might parse here only complete messages, postoponing the full parsing
          // of fragmented ones to the moment we see the full message...
          // ... but then if we do not see the rest of the message, we will never parse the first part 
//          ssl_client_parse_tls(ptp,pdata,payload_len,data_length);
        }
      
      // We opt for always parsing the fragmented message, so to already have most of the content
      // We might also, later, condition the parsing of the full message on already knowing the SNI.
      
      ssl_client_parse_tls(ptp,pdata,payload_len,data_length);

      return TRUE;
      
   }
  else if (  *(char *)(pdata + 2) == 0x01 &&
             *(char *)(pdata + 3) == 0x03 &&
           ( *(char *)(pdata + 4) >= 0x00 && *(char *)(pdata + 4) <= 0x03 )
          ) 
   { 
     /* Match SSL 2.0 Handshake CLient HELLO */
      record_length = ((*(char *)pdata & 0x7f) << 8) | ((*(char *)(pdata + 1)) & 0x00ff);
      if (record_length == payload_len-2)
        { 
	  ptp->state = SSL_HANDSHAKE;
          return TRUE;
	}
   }
  return FALSE;
}

Bool ssl_server_check(tcp_pair *ptp, void *pdata, int payload_len, int data_length)
{
  if (  payload_len >= 5 &&         // check if we have enough bytes
        *(char *)pdata == 0x16 &&   // fixed value
        *(char *)(pdata + 1) == 0x03 && 
      ( *(char *)(pdata + 2) >= 0x00 && *(char *)(pdata + 2) <= 0x03 ) && 
      ( *(char *)(pdata + 3) >= 0x00 && *(char *)(pdata + 3) <= 0x39 ) && // SSL/TLS max record size is 16kB
        *(char *)(pdata + 5) == 0x02 //Server Hello message type
     )
   { 
     /* Match SSL 3 - TLS 1.x Handshake Server HELLO */
     
     int idx = 43; // sessionID length
     int ii, all_ext_len, ext_len, ext_type, data_limit;
     int tls_message_version;
     char *base = (char *)pdata;

      // Lenght of the Hello Message, including 5 bytes for the TLS header
     int message_length = 5 + ntohs(*(tt_uint16 *)(base+3));
      
     /* TLS version in the message */
     tls_message_version = ntohs(*(tt_uint16 *)(base+9));

     sprintf(tls_version_list,"%04x",tls_message_version);
     if (ptp->ssl_server_tls_version==NULL) 
	 ptp->ssl_server_tls_version = strdup(tls_version_list);

     // printf("S <- %s\n",ptp->ssl_server_tls_version);

     /* Look for special value of ServerHello indicating a Client Hello Retry*/
     if ( payload_len > 11+32 ) /* Verify enough data is available */
      {
       char * tls_server_random =(char *)(base+11);
       if (memcmp (tls_server_random, TLS13_SERVER_HELLO_RETRY_REQUEST_MAGIC, 32) == 0 )
         ptp->ssl_server_hello_retry = TRUE; /* Set TRUE if Random = Magic */
      }

     // All tests must be limited to the Hello Message, so
     // we define the minimum between the Message Lenght and the 
     // actual data available in the segment
      
     data_limit = min(data_length,message_length);

     if (idx >= payload_len) return TRUE;

     //index of the sessionID length
     if (base[idx] == 0x00)
       idx += 1;
     else
       idx += base[idx]+1;

     //index of the start of cipher suite section
     if (idx + 2 >= data_limit) 
       return TRUE;
     idx += 2;

     //index of the start of the compression section
     if (base[idx] != 0x00)
       idx += ntohs(*(tt_uint16 *)(base+idx)) + 2; 
     else
       idx += 1;

     //total size of the extension
     if (idx + 2 >= data_limit) 
       return TRUE;
     all_ext_len = ntohs(*(tt_uint16 *)(base+idx));

     idx += 2; // 1st byte of the 1st extension
     ii = 0;
     while (ii < all_ext_len && idx < data_limit)
      {
        // extension type
        ext_type = ntohs(*(tt_uint16 *)(base+idx+ii));
        ii += 2;

        // extension length
        if (idx + ii + 2 >= data_limit) 
	  break;
        ext_len = ntohs(*(tt_uint16 *)(base+idx+ii));
        ii += 2;

        switch (ext_type) 
	 {
           // NPN (Next Protocol Negotiation)
           // the assumption in place is that if the client employ NPN, then it is for SPDY
           case 0x3374:
             if (idx + ii < data_limit) 
	       {
                 ptp->ssl_server_npnalpn |= ssl_parse_npnalpn_extension(base, idx, ii, data_limit, ext_len, TRUE);
               }
             break;
           case 0x0010:
             if (idx + ii + 2 >= data_limit) 
               return TRUE;
             // extract the protocols length
             ext_len = ntohs(*(tt_uint16 *)(base+idx+ii));
             ii += 2; 
             ptp->ssl_server_npnalpn |= ssl_parse_npnalpn_extension(base, idx, ii, data_limit, ext_len, FALSE);
             break;

           case 0x002b: /* Supported Versions (TLS Version Negotiation)*/
             if (ext_len!=0)
	     {
               if (idx + ii + 1 >= data_limit) 
                 return TRUE;
               else 
	        {
	          int tls_version_item;
	       
	          tls_version_item = ntohs(*(tt_uint16 *)(base+idx+ii));

	          sprintf(tls_version_list,"%04x",tls_version_item);

	          /* Must overwrite the message version*/ 
                  if (ptp->ssl_server_tls_version!=NULL) 
		    free(ptp->ssl_server_tls_version);
	          ptp->ssl_server_tls_version = strdup(tls_version_list);
	       
	          // printf("S -> %s\n",ptp->ssl_server_tls_version);

                }
	     }
             break;

           case 0x0029: /* Server PSK extension present */
             ptp->ssl_server_PSK = TRUE;
             break;

        // default:
        //   if (idx+next >= data_length) return TRUE;
         }
        ii += ext_len;
      }

     /* In any case, it's SSL/TLS, so we return TRUE */
     return TRUE;
   }
  return FALSE;
}

int ssl_certificate_check(tcp_pair *ptp, void *pdata, int data_length)
{
  static char cname[80];
  char *base;
  int i,j,max;
  int  done;
  
  base = (char *)pdata;
  
  if (data_length < 30 ) return 0; // Suppose the packet is large enough
  
  done = 0;
  
  for (i=0;i<data_length-7 && !done ;i++)
   {
     if (base[i]!=0x06) continue;
     if ( base[i]==0x06   && base[i+1]==0x03 && base[i+2]==0x55 && 
          base[i+3]==0x04 && base[i+4]==0x03 )
      {
        max = base[i+6];
	for (j=0;j<max && j<79 && i+j<data_length; j++)
	 {
	   cname[j]=base[i+7+j];
	 }
	cname[j]='\0';
	
	if (regexec(&re_ssl_subject,cname, (size_t) 0, NULL, 0)==0)
	  {
	    if (regexec(&re_ssl_clean,cname, (size_t) 0, NULL, 0)==0)
	       ptp->ssl_server_subject = strdup(cname);
	    done = 1;
	  }

      }
   }
  return 0;
}

Bool ssl_application_data_check(void *pdata)
{
  if (  *(char *)pdata == 0x17 && 
        *(char *)(pdata + 1) == 0x03 && 
      ( *(char *)(pdata + 2) >= 0x00 && *(char *)(pdata + 2) <= 0x03 )
     )
   {
     /* We trust that the connection has already been classified as SSL, so we just check the first bytes */
     return TRUE;
   }
  else 
     return FALSE;
}

Bool ssh_header_check(void *pdata)
{
  if (( *(char *)(pdata + 4) == 0x31 || *(char *)(pdata + 4) == 0x32 ) && 
        *(char *)(pdata + 5) == 0x2E && 
      ( *(char *)(pdata + 6) >= 0x30 && *(char *)(pdata + 6) <= 0x39 )
     )
   { 
     /* Match SSH 2.x/1.x Handshake */
      return TRUE;
   }
  return FALSE;
}

Bool is_imap_tag(void *pdata)
{
  int i;
  char c;

  /* Identify the IMAP tag with pattern /^.+[0-9A-Za-z] /
    (space after either a digit or a letter) in the first 6 chars.
     General tag identification not possible, since it can be
     any alphanumeric unique string
  */
  
  for (i=1;i<6;i++)
   {
     if ( *(char *)(pdata + i) == 0x20 )
       {
         c = *(char *)(pdata + i-1 );
	 if ( (c>=0x30 && c<=0x39) ||    /* digit */
	      (c>=0x61 && c<=0x7a) ||    /* lowercase letter */
	      (c>=0x41 && c<=0x5a) )     /* uppercase letter */
	   return TRUE;   
       }  
   }
  return FALSE;
}

void rtmp_handshake_check(tcp_pair *ptp, void *pdata, int payload_len, int dir)
{
  char c;
  
  /* Check first byte of the first data segment in both directions, */
  /* checking that it is actually the first byte even if segments are not ordered */

  if (ptp->state_rtmp_c2s_seen==1 && ptp->state_rtmp_s2c_seen==1)
    return;
    
  c = *(char *)pdata; /* First byte in the payload: 
                         must be 0x03 (unencrypted), 0x06 (encrypted) 
                         or 0x08 (further encrypted)
                         or 0x09 or 0x0a (Hulu encrypted)
		      */ 
    
  if (dir == C2S && (ptp->c2s.seq-ptp->c2s.syn-payload_len)==1 && ptp->state_rtmp_c2s_seen==0)
    { 
      ptp->state_rtmp_c2s_seen=1;
      if ( c == 0x03 || c==0x06 || c==0x08 )
         ptp->state_rtmp_c2s_hand=1;
    }

  if (dir == S2C && (ptp->s2c.seq-ptp->s2c.syn-payload_len)==1 && ptp->state_rtmp_s2c_seen==0)
    { 
      ptp->state_rtmp_s2c_seen=1;
      if ( c == 0x03 || c==0x06 || c==0x08 || c==0x09 || c==0x0a)
        ptp->state_rtmp_s2c_hand=1;
    }
    
  if ( ptp->state_rtmp_c2s_hand == 1 && ptp->state_rtmp_s2c_hand == 1)
    ptp->con_type |= RTMP_PROTOCOL;

  return;
}

void
tcpL7_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast)
{
  tcp_pair *ptp;

  void *pdata;			/*start of payload */
  int data_length, payload_len;
  tcb *tcp_stats;

  tcphdr *ptcp;
  ptcp = (tcphdr *) hdr;

  if (tproto == PROTOCOL_UDP)
    {
       return;
    }

  ptp = ((tcb *) pdir)->ptp;

  if (ptp == NULL || ptp->state == IGNORE_FURTHER_PACKETS)
    return;

/* Content of the old FindConType function */
 
  pdata = (char *) ptcp + ptcp->th_off * 4;
  payload_len = getpayloadlength (pip, plast) - ptcp->th_off * 4;
  data_length = (char *) plast - (char *) pdata + 1;

  if (data_length <= 0 || payload_len == 0)
    return;

  rtmp_handshake_check(ptp,pdata,payload_len,dir);

  if (dir == C2S)
    tcp_stats = &(ptp->c2s);
  else
    tcp_stats = &(ptp->s2c);

  switch (ptp->state)
   {
     case UNKNOWN_TYPE:
        if ((char *) pdata + 4 > (char *) plast)
	  return;
	switch (*((u_int32_t *) pdata))
	 {
            case GET:
	      if (dir == C2S)
	        {
	          tcp_stats->u_protocols.f_http = current_time;
	          ptp->state = HTTP_COMMAND;
	        }
	      break;
	    case POST:
	      if (dir == C2S)
	        {
	          tcp_stats->u_protocols.f_http = current_time;
	          ptp->state = HTTP_COMMAND;
	        }
	      break;
	    case PATCH:         /* Include also typical REST methods */
	    case OPTIONS:
	    case DELETE:
              if (dir == C2S && verify_long_method(*((u_int32_t *) pdata),pdata)==1)
	        {
	          tcp_stats->u_protocols.f_http = current_time;
	          ptp->state = HTTP_COMMAND;
	        }
	      break;
	    case HEAD:
	    case PUT:		/* Include also typical REST methods */
	      if (dir == C2S)
	        {
	          tcp_stats->u_protocols.f_http = current_time;
	          ptp->state = HTTP_COMMAND;
	        }
	      break;
            case DESC:
	      if ((dir == C2S) && ((char *) pdata + 8 <= (char *) plast))
               {
	         switch (*((u_int64_t *) pdata))
	          {
	            case DESCRIBE:
	              tcp_stats->u_protocols.f_rtsp = current_time;
	              ptp->state = RTSP_COMMAND;
	              break;
	            default:
	              break;
		  }
	       }
	      break;

            case SMTP_220:
              /* A SMTP dialog is open by the server with the "220 xxxx"
	         message 
	      */
	      if (dir == S2C)
	        {
	          ptp->state = SMTP_OPENING;
	        }
	      break;

            case POP_OK:
            case POP_ERR:
              /* A POP3 dialog is open by the server with the "+OK xxxx"
	         message. We consider also the "-ERR xxx" message, even if
		 it not probable that a server uses it to start the dialog
	      */
	      if (dir == S2C)
	        {
	          ptp->state = POP3_OPENING;
	        }
	      break;

            case IMAP_OK:
              /* An IMAP dialog is open by the server with the "*OK xxxx"
	         message 
	      */
	      if (dir == S2C)
	        {
	          ptp->state = IMAP_OPENING;
	        }
	      break;

            case SSH_HEADER: 
              /* SSH Server handshake SSH-[1-2].[0-9]
	         message 
	      */
	      if (dir == S2C &&
	         ((char *) pdata + 7 <= (char *) plast) &&
	          ssh_header_check(pdata)
	          )
	        {
	          ptp->state = SSH_SERVER;
	        }
	      break;

           default:
             if ( dir==C2S && ((char *) pdata + 6 <= (char *) plast) && ssl_client_check(ptp,pdata,payload_len,data_length) ) {
                 // check if the Client Hello message carries a sessionID
                 // 44th byte carries the length of the sessionID field
                 ptp->ssl_sessionid_reuse = FALSE;
                 if ((char *)pdata + 43 <= (char *)plast && *(char *)(pdata + 43) != 0x00)
                     ptp->ssl_sessionid_reuse = TRUE;
                 
             }
             else {
                 if (ptp->packets > MAX_UNKNOWN_PACKETS)
                     ptp->state = IGNORE_FURTHER_PACKETS;
             }
             break;
	 }
	break;
     case SMTP_OPENING:
        if (dir == C2S && ((char *) pdata + 4 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      /*
                Possible commands are HELO and EHLO
	      */
	      case SMTP_HELO:
	      case SMTP_EHLO:
	      case SMTP_helo:
	      case SMTP_ehlo:
	        ptp->con_type |= SMTP_PROTOCOL;
	        ptp->state = IGNORE_FURTHER_PACKETS;
	        break;
	      default:
	        break;
	    }
	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;
     case POP3_OPENING:
        if (dir == C2S && ((char *) pdata + 4 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      /*
	        At the opening we are in Authentication state, so
		the possible commands are USER, APOP and QUIT
	      */
	      case POP_USER:
	      case POP_QUIT:
              case POP_APOP:
	        ptp->con_type |= POP3_PROTOCOL;
	        ptp->state = IGNORE_FURTHER_PACKETS;
	        break;
	      default:
	        break;
	    }
	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;
     case IMAP_OPENING:
        if (dir == C2S && ((char *) pdata + 6 <= (char *) plast))
	 {
             if (is_imap_tag(pdata))
	     {
	        ptp->state = IMAP_COMMAND;
		break;
	     }

	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;
     case IMAP_COMMAND:
        if (dir == S2C && ((char *) pdata + 6 <= (char *) plast))
	 {
	   /* 
	     Answer to a possible IMAP command starts either with '* '
	     or with an IMAP tag 
	   */
           if ( ( ( *(char *)(pdata) == 0x2a ) && 
                    *(char *)(pdata + 1) == 0x20 ) || 
		is_imap_tag(pdata)
              )
	     {
	        ptp->con_type |= IMAP_PROTOCOL;
	        ptp->state = IGNORE_FURTHER_PACKETS;
		break;
	     }

	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;
     case HTTP_COMMAND:
        if (dir == S2C && ((char *) pdata + 4 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      case HTTP:
	        tcp_stats->u_protocols.f_http = current_time;
	        ptp->con_type |= HTTP_PROTOCOL;
	        ptp->state = HTTP_RESPONSE;
                /* store the response code, only if made of digits */
                if ((char *) pdata + 13 <= (char *) plast)
		  {
		    int idx;

                    memcpy(ptp->http_response,(char *) pdata+9,3);
		    ptp->http_response[3]='\0';
		    for (idx = 0; idx<3 ; idx++)
		      if (!isdigit(ptp->http_response[idx]))
			{
			  ptp->http_response[idx]='\0';
			  break;
			}
		    if (strlen(ptp->http_response)==0)
                      strncpy(ptp->http_response,"000",4);
		  }
                else
                  strncpy(ptp->http_response,"000",4);
	        break;
	      default:
	        break;
	    }

	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	    
	 }
	break;
     case HTTP_RESPONSE:
        if ((char *) pdata + 4 <= (char *) plast &&
            ptp->packets > MAX_HTTP_RESPONSE_PACKETS)
          ptp->state = IGNORE_FURTHER_PACKETS;
        break;
     case RTSP_COMMAND:
        if (dir == S2C && ((char *) pdata + 4 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      case RTSP:
	        tcp_stats->u_protocols.f_rtsp = current_time;
	        ptp->state = RTSP_RESPONSE;
	        ptp->con_type |= RTSP_PROTOCOL;
	        break;
	      default:
	        break;
            }
	   if (ptp->packets > MAX_RTSP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;
     case RTSP_RESPONSE:
	if (ptp->packets > MAX_RTSP_RESPONSE_PACKETS)
	  ptp->state = IGNORE_FURTHER_PACKETS;
        break;
     case SSL_HANDSHAKE:
        if (dir == C2S && ((char *) pdata + 6 <= (char *) plast))
         {
           // We should be in this state if the Client Hello was fragmented, we have seen the first fragment
           // and we still have to see the Server Hello, so the packet should be carrying the further Client Hello data
           
           if (ptp->ssl_client_hello_buffer!=NULL && ptp->ssl_client_hello_offset > 0 )
            {
              if ((ptp->ssl_client_hello_offset + data_length) == ptp->ssl_client_hello_message_len ) 
               {
                 // I have the full Client Hello message
                 /*  printf("TLS data %d offset %d message %d offset+data %d %s\n",data_length, 
                             ptp->ssl_client_hello_offset, 
                             ptp->ssl_client_hello_message_len, 
                             ptp->ssl_client_hello_offset+data_length,
                             ptp->ssl_client_subject!=NULL?ptp->ssl_client_subject:"---");
                */
                  memcpy(ptp->ssl_client_hello_buffer+ptp->ssl_client_hello_offset,pdata,data_length);
                  ptp->ssl_client_hello_offset += data_length;
                  ssl_client_parse_tls(ptp,ptp->ssl_client_hello_buffer,ptp->ssl_client_hello_offset,ptp->ssl_client_hello_offset);
               }
              else if ((ptp->ssl_client_hello_offset + data_length) < ptp->ssl_client_hello_message_len ) 
               {
                 // Some fragment still missing 
                 /* printf("TLS- data %d offset %d message %d offset+data %d %s\n",data_length, 
                            ptp->ssl_client_hello_offset, 
                            ptp->ssl_client_hello_message_len, 
                            ptp->ssl_client_hello_offset+data_length,
                            ptp->ssl_client_subject!=NULL?ptp->ssl_client_subject:"---");
                 */
                  memcpy(ptp->ssl_client_hello_buffer+ptp->ssl_client_hello_offset,pdata,data_length);
                  ptp->ssl_client_hello_offset += data_length;
                  ssl_client_parse_tls(ptp,ptp->ssl_client_hello_buffer,ptp->ssl_client_hello_offset,ptp->ssl_client_hello_offset);
               }
              else
               {
                 // More data than expected: ignore because probably the packets have been seen in the wrong sequence
                  /* 
                    printf("TLS++ data %d offset %d message %d offset+data %d %s\n",data_length, 
                            ptp->ssl_client_hello_offset,
                            ptp->ssl_client_hello_message_len, 
                            ptp->ssl_client_hello_offset+data_length,
                            ptp->ssl_client_subject!=NULL?ptp->ssl_client_subject:"---");
                  */
               }
            } 
               
         }
        if (dir == S2C && ((char *) pdata + 6 <= (char *) plast) &&
	    ssl_server_check(ptp, pdata, payload_len, data_length) )
	  {
            ssl_certificate_check(ptp,pdata,data_length);

	    ptp->con_type |= SSL_PROTOCOL;
	    ptp->state = SSL_DATA;
	  }
         else
	  {
            if (ptp->packets > MAX_SSL_HANDSHAKE_PACKETS )
	     { 
	       /* Reset SSL State */
	       ptp->state = UNKNOWN_TYPE;
	     }
	  }  
        break;

     case SSL_DATA:
        if (dir == C2S && ((char *) pdata + 6 <= (char *) plast))
	  {
            if ( !(ptp->ssl_client_data_seen) && ssl_application_data_check(pdata) )
	     {
	       ptp->ssl_client_data_time = current_time;
	       ptp->ssl_client_data_seen = TRUE;
               ptp->ssl_client_data_byte = ptp->c2s.max_seq - ptp->c2s.syn - payload_len;
	     }
	  }
	else if (dir == S2C && ((char *) pdata + 6 <= (char *) plast))
	  {
	    if (ptp->ssl_server_subject != NULL)
	     {
	       if ( *(char *)pdata == 0x16 && *(char *)(pdata + 5) == 0x0B)
	        {
                  ssl_certificate_check(ptp,pdata,data_length);
	        }
	     }

	    if ( !(ptp->ssl_server_data_seen) && ssl_application_data_check(pdata) )
	     {
	       ptp->ssl_server_data_time = current_time;
	       ptp->ssl_server_data_seen = TRUE;
	       ptp->ssl_server_data_byte = ptp->s2c.max_seq - ptp->s2c.syn - payload_len;
	     }
	  }
	  
	if (ptp->ssl_client_data_seen && ptp->ssl_server_data_seen)
	  {
	    ptp->state = IGNORE_FURTHER_PACKETS;
	  }
        break;
	
     case SSH_SERVER:
        if (dir == C2S && ((char *) pdata + 7 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      case SSH_HEADER:
	        if (ssh_header_check(pdata))
		 {
	           ptp->con_type |= SSH_PROTOCOL;
	           ptp->state = IGNORE_FURTHER_PACKETS;
		 }
	        break;
	      default:
	        break;
	    }
	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;

     default:
	break;
   }

  if (ptp->packets > MAX_PACKETS_CON)
     ptp->state = IGNORE_FURTHER_PACKETS;

  if (dir == C2S && ptp->state != IGNORE_FURTHER_PACKETS && ptp->ssl_client_data_seen != TRUE)
     ptp->ssl_client_before_data_time = current_time;
  else if (dir == S2C && ptp->state != IGNORE_FURTHER_PACKETS && ptp->ssl_server_data_seen != TRUE)
     ptp->ssl_server_before_data_time = current_time;

  return; 
}

void
make_tcpL7_conn_stats (void *thisflow, int tproto)
{
   int type;
   tcp_pair * ptp = (tcp_pair *)thisflow;

   type = map_flow_type(ptp);
   
        switch ((in_out_loc(ptp->internal_src, ptp->internal_dst, C2S)))
	{
	case OUT_FLOW:
	  add_histo (L7_TCP_num_out, type);
	  break;
	case IN_FLOW:
	  add_histo (L7_TCP_num_in, type);
	  break;
	case LOC_FLOW:
	  add_histo (L7_TCP_num_loc, type);
	  break;
	}
return;
}


/* 
   Map the bitmask of the tcpL7 classifier to the L7 types
   used by the histograms (from l7types.h)
*/

int map_flow_type(tcp_pair *thisflow)
{
   int type=L7_FLOW_UNKNOWN;


   /* RTMP  */
   if(thisflow->con_type & RTMP_PROTOCOL)
   {
     if (thisflow->c2s.msg_count>0 && thisflow->s2c.msg_count>0)
       {
         if (thisflow->c2s.msg_size[0]==1537 &&
             ( thisflow->s2c.msg_size[0]==3073 || 
	       thisflow->s2c.msg_size[0]==1537) ) 
           type = L7_FLOW_RTMP;
         else if ((thisflow->c2s.msg_size[0]+thisflow->c2s.msg_size[1])==1537 &&
               ( thisflow->s2c.msg_size[0]==3073 || 
	         thisflow->s2c.msg_size[0]==1537 ||
	         (thisflow->s2c.msg_size[0]+thisflow->s2c.msg_size[1])==3073 || 
	         (thisflow->s2c.msg_size[0]+thisflow->s2c.msg_size[1])==1537)
	       ) 
	    /* PSH-separated message definition might not be perfect, so we look
	       also at the second "message" */
           type = L7_FLOW_RTMP;
         else
          /* If con_type was set to RTMP_PROTOCOL and I already 
	     have seen the first 2 messages and if the size are wrong, the
	     flow will never be RTMP
	  */
          { 
	    if (thisflow->c2s.msg_count>1 && thisflow->s2c.msg_count>1)
               thisflow->con_type &= ~RTMP_PROTOCOL;
	  }   
       }
   }

   /* HTTP */
   if(thisflow->con_type & HTTP_PROTOCOL)
   {
      type = L7_FLOW_HTTP;
   }

   /* RTSP */
   if(thisflow->con_type & RTSP_PROTOCOL)
   {
      type = L7_FLOW_RTSP;
   }

   /* RTP */
   if(thisflow->con_type & RTP_PROTOCOL)
   {
      type = L7_FLOW_RTP;
   }

   /* RTCP */
   if(thisflow->con_type & RTCP_PROTOCOL)
   {
      type = L7_FLOW_RTCP;
   }

   /* SMTP */
   if(thisflow->con_type & SMTP_PROTOCOL)
   {
      type = L7_FLOW_SMTP;
   }

   /* POP3 */
   if(thisflow->con_type & POP3_PROTOCOL)
   {
      type = L7_FLOW_POP3;
   }

   /* IMAP */
   if(thisflow->con_type & IMAP_PROTOCOL)
   {
      type = L7_FLOW_IMAP;
   }

   /* SSL */
   if(thisflow->con_type & SSL_PROTOCOL)
   {
      type = L7_FLOW_SSL;
   }

   /* SSH */
   if(thisflow->con_type & SSH_PROTOCOL)
   {
      type = L7_FLOW_SSH;
   }

   return type;
}

void
make_tcpL7_rate_stats (tcp_pair *thisflow, int len)
{
   int type;
   type = map_flow_type(thisflow);

   if (internal_src && !internal_dst)
    {
       L7_bitrate.out[type] += len;
    }
  else if (!internal_src && internal_dst)
    {
       L7_bitrate.in[type] += len;
    }
  else if (internal_src && internal_dst)
    {
       L7_bitrate.loc[type] += len;
    }

  return;
}

void
make_udpL7_rate_stats (ucb * thisflow, int len)
{
   int type;
   type = udp_to_L7type(thisflow);

   if (internal_src && !internal_dst)
    {
       L7_udp_bitrate.out[type] += len;
    }
  else if (!internal_src && internal_dst)
    {
       L7_udp_bitrate.in[type] += len;
    }
  else if (internal_src && internal_dst)
    {
       L7_udp_bitrate.loc[type] += len;
    }

  return;
}

