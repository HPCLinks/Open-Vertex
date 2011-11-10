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
 * LATCHESAR IONKOV AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#include "spfs.h"
#include "spclient.h"

extern int spc_chatty;

static Spcfd *ispcfd;

static void
usage()
{
	fprintf(stderr, "9read -d addr path\n");
	exit(1);
}

static void
disconnect()
{
	spcfd_remove(ispcfd);
	spcfd_stop_loop();
}

static void
in_notify(Spcfd *spcfd, void *aux)
{
	int n;
	char buf[256];

	while (spcfd_can_read(spcfd)) {
		n = spcfd_read(spcfd, buf, sizeof(buf));
		if (n <= 0)
			break;

		write(1, buf, n);
	}

	if (n<=0 || spcfd_has_error(spcfd)) 
		disconnect();
}

int
main(int argc, char **argv)
{
	int c;
	char *addr;
	char *path;
	Spuser *user;
	Spcfsys *fs;
	Spcfid *fid;

	user = sp_unix_users->uid2user(sp_unix_users, geteuid());
	while ((c = getopt(argc, argv, "dp:")) != -1) {
		switch (c) {
		case 'd':
			spc_chatty = 1;
			break;

		case 'u':
			user = sp_unix_users->uname2user(sp_unix_users, optarg);
			break;

		default:
			usage();
		}
	}
	
	if (!user) {
		fprintf(stderr, "cannot retrieve user %d\n", geteuid());
		exit(1);
	}

	if (argc - optind < 2)
		usage();

	addr = argv[optind];
	path = argv[optind+1];

	fs = spc_netmount(addr, user, 564, NULL, NULL);
	fid = spc_open(fs, path, Oread);
	if (!fid) {
		fprintf(stderr, "cannot open\n");
		exit(1);
	}

	ispcfd = spcfd_add(fid, in_notify, fid, 0);
	spcfd_start_loop();
	spc_close(fid);
	spc_umount(fs);

	exit(0);
}
