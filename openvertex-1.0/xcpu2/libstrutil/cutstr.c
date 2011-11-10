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
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "strutil.h"

int
cutstr(unsigned char *target, int toffset, int tcount, char *src, int soffset)
{
	if (!src)
		return 0;

	return cutbuf(target, toffset, tcount, src, soffset, strlen(src));
}

int
cutbuf(unsigned char *target, int toffset, int tcount, char *src, int soffset, int slen)
{
	int b, e;

	if (!src)
		return 0;

	if (toffset > soffset+slen)
		return 0;

	if (soffset > toffset+tcount)
		return 0;

	b = soffset;
	if (b < toffset)
		b = toffset;

	e = soffset+slen;
	if (e > (toffset+tcount))
		e = toffset+tcount;

	memmove(target+(b-toffset), src+(b-soffset), e-b);
	return e-b;
}
