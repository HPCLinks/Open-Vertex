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
#include "spfs.h"
#include "spclient.h"
#include "spcimpl.h"

int
spc_dirread(Spcfid *fid, Spwstat **statpp)
{
	int i, n, m, buflen, statsz, slen, count;
	u8 *buf;
	char *sbuf;
	Spstat stat;
	Spwstat *statp;

	buflen = fid->fsys->msize - IOHDRSZ;
	buf = sp_malloc(buflen);
	if (!buf) 
		return -1;

	n = spc_read(fid, buf, buflen, fid->offset);
	if (n < 0) {
		free(buf);
		return n;
	}

	fid->offset += n;
	count = 0;
	i = 0;
	slen = 0;
	while (i < n) {
		statsz = sp_deserialize_stat(&stat, buf + i, buflen - i, fid->fsys->dotu);
		if (!statsz) {
			sp_werror("stat error", EIO);
			free(buf);
			return -1;
		}

		count++;
		slen += spc_wstatlen(&stat);
		i += statsz;
	}

	statp = sp_malloc(slen);
	if (!statp) {
		free(buf);
		return -1;
	}

	sbuf = ((char *) statp) + count * sizeof(Spwstat);
	i = 0;
	m = 0;
	while (i < n) {
		statsz = sp_deserialize_stat(&stat, buf + i, buflen - i, fid->fsys->dotu);
		spc_stat2wstat(&stat, &statp[m], &sbuf);
		m++;
		i += statsz;
	}

	free(buf);
	*statpp = statp;

	return count;
}
