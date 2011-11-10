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

extern int spc_chatty;

void usage(char *name) {
	fprintf(stderr, "usage: %s [-h] [-A adminkey] [-d] [-p port] <passwd|group> {-a | nodeset} \n", name);
	exit(1);
}

int
read_pwent(Xpnode *node, void *adminkey)
{
	char **pwent = NULL;
	int i, n;
	n = xp_getpwent(node, (char *)adminkey, &pwent);
	if (n < 0)
		return -1;

	printf("Password Database From Node: %s\n", node->name);
	for (i = 0; i < n; i++)
		printf("%s\n", pwent[i]);
	free(pwent);
	return 0;
}

int
read_grent(Xpnode *node, void *adminkey)
{
	char **grent = NULL;
	int i, n;
	n = xp_getgrent(node, (char *)adminkey, &grent);
	if (n < 0)
		return -1;

	printf("Group Database From Node: %s\n", node->name);
	for (i = 0; i < n; i++)
		printf("%s\n", grent[i]);
	free(grent);
	return 0;
}

int
main(int argc, char **argv)
{
	int c, ecode;
	int allflag = 0;
	char *ename, *end, db[7];
	char *adminkey = NULL;
	Xpnodeset *nds, *nds2;
	int port = STAT_PORT;

	while ((c = getopt(argc, argv, "+dA:ap:h")) != -1) {
		switch (c) {
		case 'd':
			spc_chatty = 1;
			break;

		case 'A':
			adminkey = strdup(optarg);
			break;

		case 'a':
			allflag++;
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

	if ((!allflag && argc - optind != 2 ) || (allflag && argc - optind != 1)) 
		usage(argv[0]);

	snprintf(db, 7, "%s", argv[optind++]);
	if (strcmp("passwd", db) && strcmp("group", db))
		usage(argv[0]);

	if (allflag) {
		char statserver[32];
		sprintf(statserver, "localhost!%d", port);
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
	} else
		nds = xp_nodeset_from_string(argv[optind++]);

	if (!nds)
		goto error;

	if (!nds)
		goto error;

	if (!strcmp("passwd", db)) {
		if (xp_nodeset_iterate(nds, read_pwent, adminkey) > 0)
			xp_nodeerror_print(argv[0]);
	} else {
		if (xp_nodeset_iterate(nds, read_grent, adminkey) > 0)
			xp_nodeerror_print(argv[0]);			
	}

	return 0;
 error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "Error: %s: %d\n", ename, ecode);
	return -1;
}
