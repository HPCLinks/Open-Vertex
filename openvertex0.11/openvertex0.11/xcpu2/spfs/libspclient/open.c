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

static int spc_clunk(Spcfid *fid);

Spcfid*
spc_create(Spcfsys *fs, char *path, u32 perm, int mode)
{
	int ecode;
	char *fname, *pname, *ename;
	Spfcall *tc, *rc;
	Spcfid *fid;

	pname = strdup(path);
	if (!pname)
		return NULL;

	fname = strrchr(pname, '/');
	if (fname) {
		*fname = '\0';
		fname++;
	} else {
		fname = pname;
		pname = "";
	}

	tc = NULL;
	fid = spc_walk(fs, pname);
	if (!fid) 
		goto error;

	tc = sp_create_tcreate(fid->fid, fname, perm, mode, NULL, fs->dotu);
	if (spc_rpc(fs, tc, &rc) < 0)
		goto error;

	fid->iounit = rc->iounit;
	if (!fid->iounit || fid->iounit>fid->fsys->msize-IOHDRSZ)
		fid->iounit = fid->fsys->msize-IOHDRSZ;
	fid->mode = (u8) mode;

	free(tc);
	free(rc);
	if (pname)
		free(pname);
	else
		free(fname);

	return fid;

error:
	sp_rerror(&ename, &ecode);
	if (ename)
		ename = strdup(ename);

	sp_werror(NULL, 0);
	spc_clunk(fid);
	sp_werror(ename, ecode);
	free(ename);

	free(tc);
	if (pname)
		free(pname);
	else
		free(fname);

	return NULL;
}

Spcfid*
spc_open(Spcfsys *fs, char *path, int mode)
{
	Spfcall *tc, *rc;
	Spcfid *fid;

	fid = spc_walk(fs, path);
	if (!fid)
		return NULL;

	tc = sp_create_topen(fid->fid, mode);
	if (spc_rpc(fs, tc, &rc) < 0) {
		spc_clunk(fid);
		free(tc);
		return NULL;
	}

	fid->iounit = rc->iounit;
	if (!fid->iounit || fid->iounit>fid->fsys->msize-IOHDRSZ)
		fid->iounit = fid->fsys->msize-IOHDRSZ;
	fid->mode = (u8) mode;

	free(tc);
	free(rc);

	return fid;
}

static int
spc_clunk(Spcfid *fid)
{
	Spfcall *tc, *rc;
	Spcfsys *fs;

	fs = fid->fsys;
	tc = sp_create_tclunk(fid->fid);
	if (spc_rpc(fid->fsys, tc, &rc) < 0) {
		free(tc);
		return -1;
	}

	spc_fid_free(fid);
	free(tc);
	free(rc);

	return 0;
}

int
spc_close(Spcfid *fid)
{
	spc_flush_requests(fid->fsys, fid);
	return spc_clunk(fid);
}
