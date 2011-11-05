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

u8 m2id[] = {
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 4, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 5, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 4, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 6, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 4, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 5, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 4, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 7, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 4, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 5, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 4, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 6, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 4, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 5, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 4, 
0, 1, 0, 2, 0, 1, 0, 3, 
0, 1, 0, 2, 0, 1, 0, 0,
};

Spcpool *
spc_create_pool(u32 maxid)
{
	Spcpool *p;

	p = sp_malloc(sizeof(*p));
	if (!p) 
		return NULL;

	p->maxid = maxid;
	p->msize = 32;	/* 256 ids */
	p->map = sp_malloc(p->msize);
	if (!p->map) {
		free(p);
		return NULL;
	}

	memset(p->map, 0, p->msize);
	return p;
}

void
spc_destroy_pool(Spcpool *p)
{
	if (p) {
		free(p->map);
		free(p);
	}
}

u32
spc_get_id(Spcpool *p)
{
	int i, n;
	u32 ret;
	u8 *pt;

	for(i = 0; i < p->msize; i++)
		if (p->map[i] != 0xFF)
			break;

	if (i>=p->msize && p->msize*8<p->maxid) {
		n = p->msize + 32;
		if (n*8 > p->maxid)
			n = p->maxid/8 + 1;

		pt = realloc(p->map, n);
		if (pt) {
			memset(pt + p->msize, 0, n - p->msize);
			p->map = pt;
			i = p->msize;
			p->msize = n;
		}
	}

	if (i >= p->msize)
		return p->msize;

	ret = m2id[p->map[i]];
	p->map[i] |= 1 << ret;
	ret += i * 8;

	return ret;
}

void
spc_put_id(Spcpool *p, u32 id)
{
	if (id >= p->maxid)
		return;

	p->map[id / 8] &= ~(1 << (id % 8));
}
