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
 * PRECISION INSIGHT AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include "npfs.h"
#include "npclient.h"
#include "npcimpl.h"

Npcfid *
npc_fid_alloc(Npcfsys *fs)
{
	Npcfid *ret;

	ret = malloc(sizeof(*ret));
	if (!ret) {
		np_werror(Ennomem, ENOMEM);
		return NULL;
	}

	ret->fsys = fs;
	ret->fid = npc_get_id(fs->fidpool);
	ret->offset = 0;
	ret->iounit = 0;

	npc_incref_fsys(fs);
	return ret;
}

void
npc_fid_free(Npcfid *fid)
{
	if (fid) {
		npc_put_id(fid->fsys->fidpool, fid->fid);
		npc_decref_fsys(fid->fsys);
		free(fid);
	}
}
