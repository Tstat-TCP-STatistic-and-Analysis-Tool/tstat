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

u_int32_t http_full_url = 0;
extern int log_level;
extern Bool force_create_new_outfiles;
extern Bool strict_privacy;

static int old_tcplog_level;
static int old_http_full_url;

/* Optional sets of measures in log_tcp_complete */
static struct {
  char *param_name;
  char *description;
  int  level;
} tcplog_sets[] = {
  {"tcplog_end_to_end", "End_to_end", TCP_LOG_END_TO_END},
  {"tcplog_layer7",     "Layer7",     TCP_LOG_LAYER7},
  {"tcplog_options",    "Options",    TCP_LOG_OPTIONS},
  {"tcplog_advanced",   "Advanced",   TCP_LOG_ADVANCED},
  {NULL, NULL, 0}
};

/* Parameters of removed features, accepted and ignored for compatibility
   with older configuration files */
static char *obsolete_params[] = {
  "tcplog_p2p",
  "videolog_end_to_end", "videolog_layer7", "videolog_videoinfo",
  "videolog_youtube", "videolog_options", "videolog_advanced",
  NULL
};

Bool is_obsolete_param(char *param_name, char **obsolete)
{
  int i;

  for (i = 0; obsolete[i] != NULL; i++)
    if (strcmp(param_name, obsolete[i]) == 0)
     {
       fprintf(fp_stderr, "runtime conf: warning: '%s' is obsolete and has been ignored\n",
               param_name);
       return TRUE;
     }
  return FALSE;
}

void options_parse_start_section(void) {
    extern int globals_set;

    if (globals_set!=0)
     {
       fprintf(fp_stderr,"ini reader: [options] section only valid in the runtime configuration context\n");
       exit(1);
     }

    old_tcplog_level = log_level;
    old_http_full_url = http_full_url;
}

static char *log_level_to_str(int level)
{
  static char log_level_text[80];
  int i;

  strcpy(log_level_text,"Core");

  for (i = 0; tcplog_sets[i].param_name != NULL; i++)
    if (level & tcplog_sets[i].level)
     {
       strcat (log_level_text," + ");
       strcat (log_level_text,tcplog_sets[i].description);
     }

  return log_level_text;
}

void options_parse_end_section(void) {

    if (old_tcplog_level != log_level || current_time.tv_sec == 0) {
        fprintf(fp_stdout, "[%s] TCP log level set to %d (%s)\n", 
            Timestamp(), log_level, log_level_to_str(log_level));
    }

    if (old_tcplog_level != log_level) {
        force_create_new_outfiles = TRUE;
    }
    old_tcplog_level = log_level;

    if (old_http_full_url != http_full_url ) {
        fprintf(fp_stdout, "(%s) %s HTTP URL log\n", 
            Timestamp(), (http_full_url==0) ? "Disabling" : 
                         ((http_full_url==1) ? "Enabling partial" : "Enabling full"));
    }

    if (old_http_full_url != http_full_url) {
        force_create_new_outfiles = TRUE;
    }
    old_http_full_url = http_full_url;
}

void options_parse_ini_arg(char *param_name, param_value param_value) {
    int i;

    for (i = 0; tcplog_sets[i].param_name != NULL; i++)
     {
       if (strcmp(param_name, tcplog_sets[i].param_name) != 0)
         continue;

       if (param_value.value.ivalue >= 0)
        {
          if (param_value.value.ivalue)
            log_level |= tcplog_sets[i].level;
          else
            log_level &= ~tcplog_sets[i].level;
        }
       else
        {
          fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
              param_name, param_value.value.ivalue);
        }
       return;
     }

    if (strcmp(param_name, "httplog_full_url") == 0) {
        if (param_value.value.ivalue >= 0 && param_value.value.ivalue<=2) {
            http_full_url = param_value.value.ivalue;
	    if ( strict_privacy && http_full_url!=0)
	    {
              fprintf(fp_stderr, "runtime conf: warning: Must be '%s = 0' while Strict Private mode is enabled\n", 
                param_name);
              fprintf(fp_stderr, "              Invalid value ignored\n");
	      http_full_url = 0;
	    }
        }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
    }
    else if (!is_obsolete_param(param_name, obsolete_params)) {
        fprintf(fp_stderr, "runtime conf err: '%s' - not valid command \n", param_name);
        exit(1);
    }
}
