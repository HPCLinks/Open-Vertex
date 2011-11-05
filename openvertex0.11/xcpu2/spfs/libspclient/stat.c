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

Spwstat *
spc_stat(Spcfsys *fs, char *path)
{
	Spfcall *tc, *rc;
	Spcfid *fid;
	Spwstat *st;
	char *sbuf;

	st = NULL;
	fid = spc_walk(fs, path);
	if (!fid)
		return NULL;

	tc = sp_create_tstat(fid->fid);
	if (spc_rpc(fs, tc, &rc) < 0) {
		free(tc);
		spc_close(fid);
		return NULL;
	}

	free(tc);
	st = sp_malloc(spc_wstatlen(&rc->stat));
	if (!st) {
		free(rc);
		spc_close(fid);
		return NULL;
	}

	sbuf = ((char *) st) + sizeof(*st);
	spc_stat2wstat(&rc->stat, st, &sbuf);
	free(rc);

	return st;
}
