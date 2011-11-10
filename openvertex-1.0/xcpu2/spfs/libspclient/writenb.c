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

typedef struct Spcwrite Spcwrite;
struct Spcwrite
{
	Spcfid*		fid;
	u64		offset;
	u32		count;
	u8*		buf;
	void		(*cb)(void *, int);
	void*		cba;
	Spfcall*	tc;
};

static void spc_write_cb(void *cba, Spfcall *rc);

static int
spc_send_write_request(Spcwrite *r)
{
	int n;
	Spcfid *fid;
	Spcfsys *fs;

	fid = r->fid;
	fs = fid->fsys;

	n = fid->iounit;
	if (n == 0)
		n = fs->msize - IOHDRSZ;

	if (n > r->count)
		n = r->count;

	r->tc = sp_create_twrite(fid->fid, r->offset, n, r->buf + r->offset);
	if (spc_rpcnb(fs, r->tc, spc_write_cb, r) < 0) {
		free(r->tc);
		return -1;
	}

	return 0;
}

static void
spc_write_cb(void *cba, Spfcall *rc)
{
	int n;
	Spcwrite *r;

	r = cba;
	free(r->tc);
	if (sp_haserror()) {
		(*r->cb)(r->cba, -1);
		return;
	}

	n = rc->count;
	if (n > r->count)
		n = r->count;

	(*r->cb)(r->cba, n);
	free(rc);
}

int 
spc_writenb(Spcfid *fid, u8 *buf, u32 count, u64 offset, 
	void (*cb)(void *, int), void *cba)
{
	Spcwrite *r;

	r = sp_malloc(sizeof(*r));
	if (!r) 
		return -1;

	r->fid = fid;
	r->offset = 0;
	r->count = count;
	r->buf = buf;
	r->cb = cb;
	r->cba = cba;
	r->tc = NULL;

	if (spc_send_write_request(r) < 0) {
		free(r);
		return -1;
	}

	return 0;
}
