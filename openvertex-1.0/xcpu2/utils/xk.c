/*
 * Copyright (C) 2006 by Andrey Mirtchovski <andrey@lanl.gov>
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
#include <sys/types.h>
#include <pwd.h>

#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "libxauth.h"
#include "libxcpu.h"
#include "xcpu.h"

extern int spc_chatty;

void 
usage(char *argv) {
	fprintf(stderr, "usage: %s [-dhjm] [-a adminkey] sig host:<pid|jid> [host:<pid|jid> ...]\n", argv);
	exit(1);
}

int
main(int argc, char **argv)
{
	int i, c, n, ecode, killjob;
	int signal;
	int match = 0;
	char *ename;
	Xpnodeset *ns;
	Xpproc *procs, *xp;
	char *s;
	char statserver[32];
	static Spuser *auser;
	static Xkey *akey;
	static char *adminkey = NULL;

	while ((c = getopt(argc, argv, "+dhja:m")) != -1) {
		switch (c) {
		case 'd':
			spc_chatty = 1;
			break;
		case 'j':
			killjob++;
			break;
		case 'a':
		        adminkey = optarg;
			break;
		case 'm':
		        match = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (argc - optind < 2)
		usage(argv[0]);
	
	signal = strtol(argv[optind++], &s, 10);
	if (*s != '\0') {
		fprintf(stderr, "bad signal argument %s: expected int", argv[optind-1]);
		usage(argv[0]);
	}
	
	if (adminkey) {
		akey = xauth_privkey_create(adminkey);
		if (!akey)
			goto error;
	}

	if (xp_defaultuser(&auser, &akey) < 0) {
		if (akey)
			xauth_destroy(akey);
		goto error;
	}	

	for(;optind < argc; optind++) {
		int isjid = 0;
		int pid = -1;
		char *id;
		
		s = strchr(argv[optind], ':');
		if(s) {
			*s++ = '\0';
			ns = xp_nodeset_from_string(argv[optind]);
			id = s;
		} else {
			ns = xp_nodeset_list(NULL);	/* assume all nodes when no nodelist */
			if(ns == NULL) {
				sprintf(statserver, "localhost!%d", STAT_PORT);
				ns = xp_nodeset_list(statserver);
			}
			id = argv[optind];
		}
		if(ns == NULL) {
			fprintf(stderr, "can not obtain nodeset from statfs\n");
			goto error;
		}
		isjid = (strchr(id, '/') != NULL);
		if(!isjid) {
			pid = strtol(id, &s, 10);
			if(*s != '\0' && !match) {
				fprintf(stderr, "bad process id: %s; skipping\n", id);
				continue;
			}
		}
		
		n = xp_proc_list(ns, auser, akey, &procs);
		if (n < 0) {
			fprintf(stderr, "can not obtain process list for nodeset %s; skipping\n", argv[optind]);
			continue;
		}
		for(i = 0; i < n; i++) {
		        char *tmpjid;
			char *slash;
			
			xp = &procs[i];
			if(isjid || match) {
				if (xp->xcpujid) {
					if(!match && !strcmp(xp->xcpujid, id)) {
						if (xp_proc_kill(xp, auser, akey, signal) < 0) {
							sp_rerror(&ename, &ecode);
							fprintf(stderr, "xp_proc_kill: %s.\n", ename);
						}
					} else if(match) {
						tmpjid = malloc(strlen(xp->xcpujid) + 1);
						strcpy(tmpjid, xp->xcpujid);
						slash = strchr(tmpjid, '/');
						*slash = '\0';
						if (!strcmp(tmpjid, id))
							if (xp_proc_kill(xp, auser, akey, signal) < 0) {
								sp_rerror(&ename, &ecode);
								fprintf(stderr, "xp_proc_kill: %s.\n", ename);
							}
						free(tmpjid);
					}
				}
			} else {
				if(xp->pid == pid)
					if (xp_proc_kill(xp, auser, akey, signal) < 0) {
						sp_rerror(&ename, &ecode);
						fprintf(stderr, "xp_proc_kill: %s.\n", ename);
					}
			}
		}
	}
	
	return 0;
	
error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "Error: %s: %d\n", ename, ecode);
	return 1;
}

