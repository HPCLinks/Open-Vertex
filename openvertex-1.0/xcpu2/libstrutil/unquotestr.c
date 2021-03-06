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

char *
unquotestr(char *str, char **eptr)
{
	char *s, *t;

	s = str;
	if (*s != '\'') {
		while (*s != ' ' && *s != '\t' && *s != '\n' && *s != '\0')
			s++;

		if (*s != '\0')
			*(s++) = '\0';

		if (eptr)
			*eptr = s;
		
		return str;
	}

	t = s + 1;
	while (*t != '\0') {
		if (*t == '\'') {
			if (*(t+1) != '\'') {
				break;
			} else {
				t++;
			}
		}
		
		*s = *t;
		s++; t++;
	}

	*s = '\0';
	if (*t != '\'')
		return NULL;
	else if (*t != '\0')
		t++;

	if (eptr)
		*eptr = t;

	return str;
}
