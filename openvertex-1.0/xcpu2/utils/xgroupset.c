/*
 * Copyright (C) 2007 by Latchesar Ionkov <lucho@ionkov.net>
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
#include <sys/param.h>
#include <signal.h>
#include <dirent.h>
#include <signal.h>
#include <grp.h>

#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "libxauth.h"
#include "libxcpu.h"
#include "xcpu.h"

extern int spc_chatty;

void
usage(char *name)
{
	fprintf(stderr, "usage: %s [-h] add [-A adminkey] {-a | nodeset} {-u | gname gid}\n", name);
	fprintf(stderr, "       %s [-h] delete [-A adminkey] {-a | nodeset} {-u | gname}\n", name);
	fprintf(stderr, "       %s [-h] flush [-A adminkey] {-a | nodeset}\n", name);
	exit(1);
}

int
main(int argc, char **argv)
{
	int ecode, c, port = STAT_PORT;
	char cmd[7];
	u32 gid;
	char *nodeset, *ename, *groupname;
	char *adminkey = NULL, *end;
	Xpnodeset *nds, *nds2;
	int allflag = 0, groupfile = 0;
	struct group *gr;

	while((c = getopt(argc, argv, "aA:dhup")) != -1) {
		switch(c) {
		case 'd':
			spc_chatty = 1;
			break;
		case 'A':
			adminkey = strdup(optarg);
			break;
		case 'a':
			allflag++;
			break;
		case 'u':
			groupfile++;
			break;
		case 'p':
			port = strtol(optarg, &end, 10);
			if (*end != '\0')
				usage(argv[0]);
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (argc < 2)
		usage(argv[0]);

	snprintf(cmd, 7 * sizeof(char), "%s", argv[optind++]);
	if (!strcmp("add", cmd) && !groupfile) {
		if (argc < 5)
			usage(argv[0]);
	} else if (!strcmp("delete", cmd) && !groupfile) {
		if (argc < 4)
			usage(argv[0]);
	} else if (!strcmp("flush", cmd) || groupfile)
		;
	else
		usage(argv[0]);
 
	if (!allflag && ((nodeset = getenv("NODES")) == NULL)) {
		if ((argc - optind) < 1 && !groupfile)
			usage(argv[0]);
		nodeset = argv[optind++];
	}

	if (allflag) {
		char statserver[32];
		sprintf(statserver, "localhost!%d", port);
		nds = xp_nodeset_list(NULL);
		if (nds == NULL)
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
	} else
		nds = xp_nodeset_from_string(nodeset);

	if (!nds)
		goto error;

	if (!strcmp("flush", cmd)) {
		if (xp_group_flush(nds, adminkey) < 0)
			goto error;
	} else if (!strcmp("delete", cmd)) {
		if (groupfile) {
			setgrent();
			while ((gr = getgrent()) != NULL)
				xp_group_del(nds, adminkey, gr->gr_name);
			endgrent();
		} else {
			if ((argc - optind) < 1)
				usage(argv[0]);
			groupname = argv[optind++];
			if (xp_group_del(nds, adminkey, groupname) < 0)
				return -1;
		}
	} else { /* group add */
		if (groupfile) {
			setgrent();
			while ((gr = getgrent()) != NULL)
				xp_group_add(nds, adminkey, gr->gr_name, gr->gr_gid);
			endgrent();
		} else {
			if ((argc - optind) < 2)
				usage(argv[0]);
			groupname = argv[optind++];
			gid = strtol(argv[optind++], NULL, 10);
			if (xp_group_add(nds, adminkey, groupname, gid) < 0)
				return -1;
		}
	}
	return 0;
error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "Error: %s\n", ename);
	return -1;
}
