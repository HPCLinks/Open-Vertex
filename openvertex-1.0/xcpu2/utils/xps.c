/*
 * Copyright (C) 2006 by Latchesar Ionkov <lucho@ionkov.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * LATCHESAR IONKOV AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <signal.h>
#include <regex.h>
#include <math.h>

#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "libxauth.h"
#include "libxcpu.h"
#include "xcpu.h"

static void printpinfo(Xpproc *xp, char *stat);

extern int spc_chatty;

void usage() {
	fprintf(stderr, "usage: xps [-dax] [-p port] [-J JobId] host,...\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int i, n, c, jlen, ecode;
	int min, sec, allflag = 0;
	long long int t;
	int xonly = 0, port = STAT_PORT;
	char *ename, buf[1024], *jobid, *end;
	Xpnodeset *nds, *nds2;
	Xpproc *procs, *xp;
	char stat[32];
	char tim[64];
	static Spuser *auser;
	static Xkey *akey;

	jlen = 0;
	jobid = NULL;
	while ((c = getopt(argc, argv, "+daxp:J:h")) != -1) {
		switch (c) {
		case 'd':
			spc_chatty = 1;
			break;

		case 'a':
			allflag++;
			break;

		case 'J':
		        if (*optarg != '/') 
		          snprintf(buf, sizeof(buf), "/%s", optarg);
	                else 
		          snprintf(buf, sizeof(buf), "%s", optarg);
			
			jobid = buf;
			jlen = strlen(jobid);
			break;

 	        case 'x':
		        xonly = 1;
	                break;

		case 'p':
			port = strtol(optarg, &end, 10);
			if (*end != '\0')
				usage(argv[0]);
			break;
		case 'h':
		default:
			usage();
		}
	}

	if (allflag) {
		char statserver[32];
		sprintf(statserver, "localhost!%d", STAT_PORT);
		nds = xp_nodeset_list(NULL);
		if(nds == NULL)
			nds = xp_nodeset_list(statserver);
		if (nds != NULL) {
			nds2 = xp_nodeset_create();
			if (nds2 != NULL) {
				if (xp_nodeset_filter_by_state(nds2, nds, "up") >= 0) {
					free(nds);
					nds = nds2;
				} else {
					free(nds2);
				}
			} /* if filter is unsuccessful just use the full set */
		}
	} else {
		if (optind >= argc)
			usage();

		nds = xp_nodeset_from_string(argv[optind++]);
	}

	if (!nds)
		goto error;

	if (xp_defaultuser(&auser, &akey) < 0)
		goto error;

	n = xp_proc_list(nds, auser, akey, &procs);
	if (n < 0)
		goto error;

	
	printf("NODE\tPID\tTTY\tSTAT\tTIME\tJOBID\tCOMMAND\n");
	for(i = 0; i < n; i++) {

	  xp = &procs[i];
	  
	  if (jobid && (!xp->xcpujid || strncmp(jobid, xp->xcpujid, jlen)))
	    continue;
	  else if (xonly && !xp->xcpujid)
	    continue;
	  	  
	  switch (xp->state) {
	  case Running:
	    stat[0] = 'R';
	    break;
	  case Sleeping:
	    stat[0] = 'S';
	    break;
	  case Zombie:
	    stat[0] = 'Z';
	    break;
	  case Stopped:
	    stat[0] = 'T';
	    break;
	  case Waiting:
	    stat[0] = 'D';
	    break;
	  default:
	    stat[0] = '?';
	  }
	  
	  stat[1] = '\0';
	  if (xp->nice < 0)
	    strcat(stat, "<");
	  else if (xp->nice > 0)
	    strcat(stat, "N");
	  if (xp->psid == xp->pid)
	    strcat(stat, "s");
	  if (xp->pgrp == xp->tpgid)
	    strcat(stat, "+");
	  
	  t = xp->utime + xp->stime;
	  min = t/(60*1000);
	  sec = t/1000 - min*60;
	  snprintf(tim, sizeof(tim), "%d:%02d", min, sec);
	  printf("%s\t%d\t%s\t%s\t%s\t%s\t%s\n", xp->node->name, xp->pid,
		 xp->tty, stat, tim, xp->xcpujid?xp->xcpujid:"", xp->cmdline);
	  
	}
	
	return 0;
	
 error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "Error: %s: %d\n", ename, ecode);
	return 1;
}
