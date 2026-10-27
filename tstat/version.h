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


/* version information */
#define VERSION_MAJOR  3
#define VERSION_MINOR  3
#define VERSION_BUGFIX 0
#define VERSION_DATE   "Mon Nov 15 14:53:42 CET 2021"
#define VERSION_FLAVOR "Voynich"
#define PACKAGE_VERSION "3.3.0"

/* the string to print */
#define VERSION  "TNG tstat-" PACKAGE_VERSION " (" VERSION_FLAVOR " flavor) -- " VERSION_DATE

/* build information */
/* constants filled in when version.c is compiled */
extern char *built_bywhom;
extern char *built_when;
extern char *built_where;
