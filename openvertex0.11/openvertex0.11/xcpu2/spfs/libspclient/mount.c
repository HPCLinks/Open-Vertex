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
#include <sys/socket.h>
#include "spfs.h"
#include "spclient.h"
#include "spcimpl.h"

Spcfsys*
spc_mount(int fd, char *aname, Spuser *user, 
	int (*auth)(Spcfid *afid, Spuser *user, void *aux), void *aux)
{
	Spcfsys *fs;
	Spfcall *tc, *rc;

	fs = spc_create_fsys(fd, spc_msize);
	if (!fs)
		return NULL;

	tc = sp_create_tversion(spc_msize, "9P2000.u");
	if (spc_rpc(fs, tc, &rc) < 0)
		goto error;

	if (rc->version.len==8 && !memcmp(rc->version.str, "9P2000.u", 8)) {
		fs->dotu = 1;
	} else if (rc->version.len==6 && !memcmp(rc->version.str, "9P2000", 6)) {
		fs->dotu = 0;
	} else {
		sp_werror("unsupported 9P version", EIO);
		goto error;
	}

	if (fs->msize > rc->msize)
		fs->msize = rc->msize;

	free(tc);
	free(rc);
	tc = rc = NULL;

	if (auth) {
		fs->afid = spc_fid_alloc(fs);
		if (!fs->afid)
			goto error;

		tc = sp_create_tauth(fs->afid->fid, user?user->uname:NULL, aname, 
			user?user->uid:-1, fs->dotu);
		if (spc_rpc(fs, tc, &rc) < 0) {
			sp_werror(NULL, 0);
			spc_fid_free(fs->afid);
			fs->afid = NULL;
		} else if ((*auth)(fs->afid, user, aux) < 0)
				goto error;

		free(tc);
		free(rc);
		tc = rc = NULL;
	}

	fs->root = spc_fid_alloc(fs);
	if (!fs->root) 
		goto error;

	tc = sp_create_tattach(fs->root->fid, fs->afid?fs->afid->fid:NOFID, 
		user->uname, aname, user->uid, fs->dotu);
	if (spc_rpc(fs, tc, &rc) < 0)
		goto error;

	free(tc);
	free(rc);
	return fs;

error:
	free(tc);
	free(rc);
	spc_disconnect_fsys(fs);
	return NULL;
}

void
spc_umount(Spcfsys *fs)
{
	spc_disconnect_fsys(fs);
	spc_destroy_fsys(fs);
}
