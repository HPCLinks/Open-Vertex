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

#define BSIZE 8192

extern int spc_chatty;

static int done;
static Spcfid *fid;
static u64 offset;
static u8 buf1[BSIZE];
static u8 buf2[BSIZE];
static u8 buf3[BSIZE];
static u8 buf4[BSIZE];
static int cnt;

static int readnb(void *buf);

static void
usage()
{
	fprintf(stderr, "9readnb -d addr path\n");
	exit(1);
}

static void
cb(void *a, int count)
{
	u8 *buf;

	buf = a;
	fprintf(stderr, "cb %d\n", count);
	if (count < 0) {
		fprintf(stderr, "error\n");
		done++;
	} else if (count > 0) {
		write(1, buf, count);
		cnt += count;
		fprintf(stderr, "%d\n", cnt);
		readnb(buf);
	} else
		done++;
}

static int
readnb(void *buf)
{
	u64 off;

	off = offset;
	offset += BSIZE;

	if (spc_readnb(fid, buf, BSIZE, off, cb, buf) < 0)
		return -1;

	return 0;
}

int
main(int argc, char **argv)
{
	int ecode;
	int c;
	char *addr;
	char *ename, *path;
	Spuser *user;
	Spcfsys *fs;

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

	if (readnb(buf1) < 0)
		goto error;

	if (readnb(buf2) < 0)
		goto error;

	if (readnb(buf3) < 0)
		goto error;

	if (readnb(buf4) < 0)
		goto error;

	while (done < 4)
		sp_poll_once();

	spc_close(fid);
	spc_umount(fs);

	return 0;

error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "Error: %s\n", ename);
	return -1;

}

