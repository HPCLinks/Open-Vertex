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
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include "spfs.h"
#include "spfsimpl.h"

static Spuser *currentUser;

void
sp_user_incref(Spuser *u)
{
	if (!u)
		return;

	u->refcount++;
}

void
sp_user_decref(Spuser *u)
{
	int i;
	if (!u)
		return;

	u->refcount--;
	if (u->refcount > 0)
		return;

	if (u->upool->udestroy)
		(*u->upool->udestroy)(u->upool, u);

	for(i = 0; i < u->ngroups; i++)
		sp_group_decref(u->groups[i]);

	sp_group_decref(u->dfltgroup);
	free(u->groups);
	free(u);
}

void
sp_group_incref(Spgroup *g)
{
	if (!g)
		return;

	g->refcount++;
}

void
sp_group_decref(Spgroup *g)
{
	if (!g)
		return;

	g->refcount--;
	if (g->refcount > 0)
		return;

	if (g->upool->gdestroy)
		(*g->upool->gdestroy)(g->upool, g);

	free(g);
}

int
sp_change_user(Spuser *u)
{
	int i;
	gid_t *gids;

	if (geteuid() == u->uid && u->dfltgroup && getegid() == u->dfltgroup->gid)
		return 0;

	if (setreuid(0, 0) < 0) 
		goto error;

	gids = sp_malloc(u->ngroups * sizeof(gid_t));
	if (!gids)
		return -1;

	for(i = 0; i < u->ngroups; i++)
		gids[i] = u->groups[i]->gid;

	if (u->ngroups > 0)
		setgroups(u->ngroups, gids);

	if (u->dfltgroup && setregid(-1, u->dfltgroup->gid)<0)
		goto error;

	if (setreuid(-1, u->uid) < 0)
		goto error;

	sp_user_incref(u);
	sp_user_decref(currentUser);
	currentUser = u;
	return 0;

error:
	sp_uerror(errno);
	return -1;
}

Spuser *
sp_current_user(void)
{
	return currentUser;
}
