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
#include <ctype.h>
#include "strutil.h"

int 
parse_range(char *range, char ***toks)
{
	int n, b, e;
	char *s, *t, *p, *ss;

	s = range;
	while (*s != '[') {
		if (*s == '\0')
			return tokenize(range, toks);
		s++;
	}

	t = strchr(s, ']');
	if (!t)
		return -1;
	
	if (*(t+1) != '\0')
		return -1;
	
	*t = '\0';
	t = strchr(s, '-');
	if (!t)
		return -1;
	
	*t = '\0';
	t++;
	
	b = strtol(s + 1, &ss, 10);
	if (*ss != '\0')
		return -1;
	
	e = strtol(t, &ss, 10);
	if (*ss != '\0')
		return -1;
	
	p = malloc(((s-range+1) + strlen(t)) * (e-b+1));
	if (!p)
		return -1;
	
	*p = '\0';
	for (n = b; n <= e; n++) {
		strncat(p, range, (s-range));
		sprintf(s, "%d ", n);
		strncat(p, s, strlen(s));
	}
	n = tokenize(p, toks);
	free(p);
	return n;
}
