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
#include <errno.h>
#include <stdarg.h>
#include "spfs.h"

char *Enomem = "not enough memory";

/* vasprintf fails on some RHEL distros ... hence the static */
static char sp_ename[1024];
static int sp_ecode;

void *
sp_malloc(int size)
{
	void *ret;

	ret = malloc(size);
	if (!ret)
		sp_werror(Enomem, ENOMEM);

	return ret;
}

static void
sp_vwerror(char *ename, int ecode, va_list ap)
{
	sp_ecode = ecode;
	if (ename) {
		vsnprintf(sp_ename, sizeof(sp_ename), ename, ap);
	}
}

void
sp_werror(char *ename, int ecode, ...)
{
	va_list ap;

	va_start(ap, ecode);
	sp_vwerror(ename, ecode, ap);
	va_end(ap);
}

void
sp_rerror(char **ename, int *ecode)
{
	*ename = NULL;
	if (sp_ecode)
		*ename = sp_ename;
	*ecode = sp_ecode;
}

int
sp_haserror()
{
	return sp_ecode != 0;
}

void
sp_uerror(int ecode)
{
	char *ename;

	ename = strerror(ecode);
	sp_werror(ename, ecode);
}

void
sp_suerror(char *s, int ecode)
{
	char err[1024];
	char buf[1024];

	strerror_r(ecode, err, sizeof(err));
	snprintf(buf, sizeof(buf), "%s: %s", s, err);
	sp_werror(buf, ecode);
}
