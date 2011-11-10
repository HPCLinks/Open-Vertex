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

static Spuser *sp_unix_uname2user(Spuserpool *, char *uname);
static Spuser *sp_unix_uid2user(Spuserpool *, u32 uid);
static Spgroup *sp_unix_gname2group(Spuserpool *, char *gname);
static Spgroup *sp_unix_gid2group(Spuserpool *, u32 gid);
static int sp_unix_ismember(Spuserpool *, Spuser *u, Spgroup *g);
static void sp_unix_udestroy(Spuserpool *, Spuser *);
static void sp_unix_gdestroy(Spuserpool *, Spgroup *);
static int sp_init_user_groups(Spuser *u);

static Spuserpool upool = {
	.uname2user = sp_unix_uname2user,
	.uid2user = sp_unix_uid2user,
	.gname2group = sp_unix_gname2group,
	.gid2group = sp_unix_gid2group,
	.ismember = sp_unix_ismember,
	.udestroy = sp_unix_udestroy,
	.gdestroy = sp_unix_gdestroy,
};

Spuserpool *sp_unix_users = &upool;

static struct Spusercache {
	int		init;
	int		hsize;
	Spuser**	htable;
} usercache = { 0 };

static struct Spgroupcache {
	int		init;
	int		hsize;
	Spgroup**	htable;
} groupcache = { 0 };

static void
initusercache(void)
{
	if (!usercache.init) {
		usercache.hsize = 2024;
		usercache.htable = calloc(usercache.hsize, sizeof(Spuser *));
		usercache.init = 1;
	}
}

static void
initgroupcache(void)
{
	if (!groupcache.init) {
		groupcache.hsize = 2048;
		groupcache.htable = calloc(groupcache.hsize, sizeof(Spgroup *));
		if (!groupcache.htable) {
			sp_werror(Enomem, ENOMEM);
			return;
		}
		groupcache.init = 1;
	}
}

static Spuser *
sp_unix_uname2user(Spuserpool *up, char *uname)
{
	int i, n;
	struct passwd pw, *pwp;
	int bufsize;
	char *buf;
	Spuser *u;

	if (!usercache.init)
		initusercache();

	for(i = 0; i<usercache.hsize; i++)
		for(u = usercache.htable[i]; u != NULL; u = u->next)
			if (strcmp(uname, u->uname) == 0)
				goto done;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize < 2024)
		bufsize = 2024;

	buf = sp_malloc(bufsize);
	if (!buf)
		return NULL;

	i = getpwnam_r(uname, &pw, buf, bufsize, &pwp);
	if (i) {
		sp_uerror(i);
		free(buf);
		return NULL;
	}

	u = sp_malloc(sizeof(*u) + strlen(pw.pw_name) + 1);
	if (!u) {
		free(buf);
		return NULL;
	}

	u->refcount = 1;
	u->upool = up;
	u->uid = pw.pw_uid;
	u->uname = (char *)u + sizeof(*u);
	strcpy(u->uname, pw.pw_name);
	u->dfltgroup = (*up->gid2group)(up, pw.pw_gid);

	u->ngroups = 0;
	u->groups = NULL;
	sp_init_user_groups(u);

	n = u->uid % usercache.hsize;
	u->next = usercache.htable[n];
	usercache.htable[n] = u;

	free(buf);

done:
	sp_user_incref(u);
	return u;
}

static Spuser *
sp_unix_uid2user(Spuserpool *up, u32 uid)
{
	int n, i;
	Spuser *u;
	struct passwd pw, *pwp;
	int bufsize;
	char *buf;

	if (!usercache.init)
		initusercache();

	n = uid % usercache.hsize;
	for(u = usercache.htable[n]; u != NULL; u = u->next)
		if (u->uid == uid)
			goto done;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize < 2048)
		bufsize = 2048;

	buf = sp_malloc(bufsize);
	if (!buf)
		return NULL;

	i = getpwuid_r(uid, &pw, buf, bufsize, &pwp);
	if (i) {
		sp_uerror(i);
		free(buf);
		return NULL;
	}

	u = sp_malloc(sizeof(*u) + strlen(pw.pw_name) + 1);
	if (!u) {
		free(buf);
		return NULL;
	}

	u->refcount = 1;
	u->upool = up;
	u->uid = uid;
	u->uname = (char *)u + sizeof(*u);
	strcpy(u->uname, pw.pw_name);
	u->dfltgroup = up->gid2group(up, pw.pw_gid);

	u->ngroups = 0;
	u->groups = NULL;
	sp_init_user_groups(u);

	u->next = usercache.htable[n];
	usercache.htable[n] = u;

	free(buf);

done:
	sp_user_incref(u);
	return u;
}

static Spgroup *
sp_unix_gname2group(Spuserpool *up, char *gname)
{
	int i, n;
	int bufsize = 2048;
	Spgroup *g;
	struct group grp, *pgrp;
	char *buf;

	if (!groupcache.init)
		initgroupcache();

	for(i = 0; i < groupcache.hsize; i++) 
		for(g = groupcache.htable[i]; g != NULL; g = g->next)
			if (strcmp(g->gname, gname) == 0)
				goto done;

	bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (bufsize < 2048)
		bufsize = 2048;

	buf = sp_malloc(bufsize);
	if (!buf)
		return NULL;

	i = getgrnam_r(gname, &grp, buf, bufsize, &pgrp);
	if (i) {
		sp_uerror(i);
		free(buf);
		return NULL;
	}

	g = sp_malloc(sizeof(*g) + strlen(grp.gr_name) + 1);
	if (!g) {
		free(buf);
		return NULL;
	}

	g->refcount = 1;
	g->upool = up;
	g->gid = grp.gr_gid;
	g->gname = (char *)g + sizeof(*g);
	strcpy(g->gname, grp.gr_name);

	n = g->gid % groupcache.hsize;
	g->next = groupcache.htable[n];
	groupcache.htable[n] = g;

	free(buf);

done:
	sp_group_incref(g);
	return g;
}

static Spgroup *
sp_unix_gid2group(Spuserpool *up, u32 gid)
{
	int n, err;
	Spgroup *g;
	struct group grp, *pgrp;
	int bufsize;
	char *buf;

	if (!groupcache.init)
		initgroupcache();

	n = gid % groupcache.hsize;
	for(g = groupcache.htable[n]; g != NULL; g = g->next)
		if (g->gid == gid) 
			goto done;

	bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (bufsize < 2048)
		bufsize = 2048;

	buf = sp_malloc(bufsize);
	if (!buf)
		return NULL;

	err = getgrgid_r(gid, &grp, buf, bufsize, &pgrp);
	if (err) {
		sp_uerror(err);
		free(buf);
		return NULL;
	}

	g = sp_malloc(sizeof(*g) + strlen(grp.gr_name) + 1);
	if (!g) {
		free(buf);
		return NULL;
	}

	g->refcount = 1;
	g->upool = up;
	g->gid = grp.gr_gid;
	g->gname = (char *)g + sizeof(*g);
	strcpy(g->gname, grp.gr_name);

	g->next = groupcache.htable[n];
	groupcache.htable[n] = g;

	free(buf);

done:
	sp_group_incref(g);
	return g;
}

static int
sp_unix_ismember(Spuserpool *up, Spuser *u, Spgroup *g)
{
	int i;

	if (!u->groups && sp_init_user_groups(u)<0)
		return -1;

	for(i = 0; i < u->ngroups; i++) {
		if (g == u->groups[i])
			return 1;
	}

	return 0;
}

static void
sp_unix_udestroy(Spuserpool *up, Spuser *u)
{
}

static void
sp_unix_gdestroy(Spuserpool *up, Spgroup *g)
{
}

static int
sp_init_user_groups(Spuser *u)
{
	int i, n=0;
	int maxgroups = 1024; /* warning: configurable in kernel */
	Spgroup **grps;
	struct group *g;
	gid_t gids[maxgroups];

	free(u->groups);
	u->ngroups = 0;

	setgrent(); 
	
	if(u->dfltgroup)
		gids[0] = u->dfltgroup->gid;
	
	while ((g = getgrent()) != NULL) { 
		for (i = 0; g->gr_mem[i]; i++) { 
			if (strcmp(u->uname, g->gr_mem[0]) == 0) { 
				n++; 
				if(n < maxgroups) 
					gids[n] = g->gr_gid; 
			}
		}
	}
	
	endgrent();

	grps = sp_malloc(sizeof(*grps) * (n+1));
	if (!grps) {
		free(gids);
		return -1;
	}
	
	for(i = 0; i <= n; i++) {
		grps[i] = u->upool->gid2group(u->upool, gids[i]);
		if (!grps[i]) {
			free(grps);
			return -1;
		}
	}
	
	u->groups = grps;
	u->ngroups = n;
	return 0;
}
