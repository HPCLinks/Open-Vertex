/*
 * Copyright (C) 2005 by Latchesar Ionkov <lucho@ionkov.net>
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
 * PRECISION INSIGHT AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "npfs.h"
#include "npclient.h"

extern int npc_chatty;

static void
usage()
{
	fprintf(stderr, "9write -d -p port addr path\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int sfd, i, n, off;
	int c, port;
	char *addr, *s;
	char *uname, *path;
	Npuser *user;
	Npcfsys *fs;
	Npcfid *fid;
	struct sockaddr_in saddr;
	struct hostent *hostinfo;
	char buf[512];

	port = 564;
//	npc_chatty = 1;

	user = np_uid2user(geteuid());
	if (!user) {
		fprintf(stderr, "cannot retrieve user %d\n", geteuid());
		exit(1);
	}

	uname = user->uname;
	while ((c = getopt(argc, argv, "dp:")) != -1) {
		switch (c) {
		case 'd':
			npc_chatty = 1;
			break;

		case 'p':
			port = strtol(optarg, &s, 10);
			if (*s != '\0')
				usage();
			break;

		case 'u':
			uname = optarg;
			break;

		default:
			usage();
		}
	}

	

	if (argc - optind < 2)
		usage();

	addr = argv[optind];
	path = argv[optind+1];

	sfd = socket(PF_INET, SOCK_STREAM, 0);
	if (sfd < 0) {
		perror("socket");
		exit(1);
	}

	hostinfo = gethostbyname (addr);
	if (!hostinfo) {
		perror("gethostbyname");
		exit(1);
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr = *(struct in_addr *) hostinfo->h_addr;

	if (connect(sfd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		perror("connect");
		exit(1);
	}

	fs = npc_mount(sfd, NULL, "lucho");

	fid = npc_open(fs, path, Owrite);
	if (!fid) {
		fid = npc_create(fs, path, 0666, Owrite);
		if (!fid) {
			fprintf(stderr, "error creating\n");
			exit(1);
		}
	}

	off = 0;
	while ((n = read(0, buf, sizeof(buf))) > 0) {
		i = npc_write(fid, (u8*) buf, n, off);
		if (i != n) {
			fprintf(stderr, "error writing\n");
			exit(1);
		}

		off += n;
	}
			
	npc_close(fid);
	npc_umount(fs);

	exit(0);
}

