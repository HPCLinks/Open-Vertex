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

typedef struct Upool Upool;

struct Upool {
	Spuser*		users;
	Spgroup*	groups;
};

static char *Euserexists = "user exists";
static char *Egroupexists = "group exists";
static char *Egroupbusy = "group not empty";

static Spuser *sp_priv_uname2user(Spuserpool *up, char *uname);
static Spuser *sp_priv_uid2user(Spuserpool *up, u32 uid);
static Spgroup *sp_priv_gname2group(Spuserpool *up, char *gname);
static Spgroup *sp_priv_gid2group(Spuserpool *up, u32 gid);
static int sp_priv_ismember(Spuserpool *up, Spuser *u, Spgroup *g);
static void sp_priv_udestroy(Spuserpool *up, Spuser *);
static void sp_priv_gdestroy(Spuserpool *up, Spgroup *);

Spuserpool *
sp_priv_userpool_create()
{
	Spuserpool *up;

	up = sp_malloc(sizeof(Spuserpool) + sizeof(Upool));
	if (!up)
		return NULL;

	up->aux = (char *)up + sizeof(Spuserpool);
	up->uname2user = sp_priv_uname2user;
	up->uid2user = sp_priv_uid2user;
	up->gname2group = sp_priv_gname2group;
	up->gid2group = sp_priv_gid2group;
	up->ismember = sp_priv_ismember;
	up->udestroy = sp_priv_udestroy;
	up->gdestroy = sp_priv_gdestroy;

	return up;
}

Spuser *
sp_priv_user_add(Spuserpool *up, char *uname, u32 uid, void *aux)
{
	Spuser *u;
	Upool *upp;

	upp = up->aux;
	u = up->uname2user(up, uname);
	if (u) {
		sp_user_decref(u);
		sp_werror("%s:%s", EIO, uname, Euserexists);
		return NULL;
	}

	u = up->uid2user(up, uid);
	if (u) {
		sp_user_decref(u);
		sp_werror("%d:%s", EIO, uid, Euserexists);
		return NULL;
	}

	u = sp_malloc(sizeof(*u) + strlen(uname) + 1);
	if (!u)
		return NULL;

	u->refcount = 1;
	u->upool = up;
	u->uid = uid;
	u->uname = (char *)u + sizeof(*u);
	strcpy(u->uname, uname);
	u->dfltgroup = NULL;
	u->ngroups = 0;
	u->groups = NULL;
	u->aux = aux;
	u->next = upp->users;
	upp->users = u;

	sp_user_incref(u);
	return u;
}

void sp_priv_user_del(Spuser *u)
{
	Spuser *tu, *pu;
	Upool *upp;

	upp = u->upool->aux;

	if (!upp->users)
		return;

	for(pu = NULL, tu = upp->users; tu != NULL; pu = tu, tu = tu->next)
		if (tu == u)
			break;

	if (!pu)
		upp->users = u->next;
	else
		pu->next = u->next;

	sp_user_decref(u);
}

Spuser *
sp_priv_user_list(Spuserpool *up)
{
	Upool *upp;

	upp = up->aux;
	
	if (!upp->users)
		return NULL;	
	
	return upp->users;
}

int
sp_priv_user_setdfltgroup(Spuser *u, Spgroup *g)
{
	if (u->dfltgroup)
		sp_group_decref(u->dfltgroup);

	u->dfltgroup = g;	/* refcount should be adjusted already */
	return 0;
}

Spgroup *
sp_priv_group_add(Spuserpool *up, char *gname, u32 gid)
{
	Spgroup *g;
	Upool *upp;

	upp = up->aux;
	g = up->gname2group(up, gname);
	if (g) {
		sp_group_decref(g);
		sp_werror("%s:%s", EIO, gname, Egroupexists);
		return NULL;
	}

	g = up->gid2group(up, gid);
	if (g) {
		sp_group_decref(g);
		sp_werror("%d:%s", EIO, gid, Egroupexists);
		return NULL;
	}

	g = sp_malloc(sizeof(*g) + strlen(gname) + 1);
	if (!g)
		return NULL;

	g->refcount = 1;
	g->upool = up;
	g->gid = gid;
	g->gname = (char *)g + sizeof(*g);
	strcpy(g->gname, gname);
	g->next = upp->groups;
	upp->groups = g;

	sp_group_incref(g);
	return g;
}

void
sp_priv_group_del(Spgroup *g)
{
	int i;
	Spgroup *tg, *pg;
	Spuser *tu;
	Upool *upp;

	upp = g->upool->aux;

	if (!upp->groups)
		return;

	for(pg = NULL, tg = upp->groups; tg != NULL; pg = tg, tg = tg->next)
		if (tg == g)
			break;

	for(tu = upp->users; tu != NULL; tu = tu->next) {
		if(!strcmp("xcpu-admin", tu->uname))
			continue;
		
		for(i = 0; i < tu->ngroups; i++) {
			if (tu->groups[i] == g) {
				sp_werror("%s:%s", EIO, g->gname, Egroupbusy);
				return;
			}
		}
	}

	if (!pg)
		upp->groups = g->next;
	else
		pg->next = g->next;

	sp_group_decref(g);
}

Spgroup *
sp_priv_group_list(Spuserpool *up)
{
	Upool *upp;

	upp = up->aux;
	
	if (!upp->groups)
		return NULL;	
	
	return upp->groups;
}

int
sp_priv_group_adduser(Spgroup *g, Spuser *u)
{
	Spgroup **grps;

	if (u->upool->ismember(u->upool, u, g))
		return 0;

	grps = realloc(u->groups, sizeof(Spgroup *) * (u->ngroups + 1));
	if (!grps) {
		sp_werror(Enomem, ENOMEM);
		return -1;
	}

	grps[u->ngroups] = g;	/* refcount should be updated already */
	u->ngroups++;
	u->groups = grps;
	return 0;
}

int
sp_priv_group_deluser(Spgroup *g, Spuser *u)
{
	int i;

	for(i = 0; i < u->ngroups; i++)
		if (u->groups[i] == g) {
			memmove(&u->groups[i], &u->groups[i+1], 
				sizeof(Spgroup*) * (u->ngroups - i - 1));

			u->ngroups--;
			break;
		}

	return 0;
}

static Spuser *
sp_priv_uname2user(Spuserpool *up, char *uname)
{
	Spuser *u;
	Upool *upp;

	upp = up->aux;
	for(u = upp->users; u != NULL; u = u->next)
		if (strcmp(u->uname, uname) == 0) {
			sp_user_incref(u);
			return u;
		}

	return NULL;
}

static Spuser *
sp_priv_uid2user(Spuserpool *up, u32 uid)
{
	Spuser *u;
	Upool *upp;

	upp = up->aux;
	for(u = upp->users; u != NULL; u = u->next)
		if (u->uid == uid) {
			sp_user_incref(u);
			return u;
		}

	return NULL;
}

static Spgroup *
sp_priv_gname2group(Spuserpool *up, char *gname)
{
	Spgroup *g;
	Upool *upp;

	upp = up->aux;
	for(g = upp->groups; g != NULL; g = g->next)
		if (strcmp(g->gname, gname) == 0) {
			sp_group_incref(g);
			return g;
		}

	return NULL;
}

static Spgroup *
sp_priv_gid2group(Spuserpool *up, u32 gid)
{
	Spgroup *g;
	Upool *upp;

	upp = up->aux;
	for(g = upp->groups; g != NULL; g = g->next)
		if (g->gid == gid) {
			sp_group_incref(g);
			return g;
		}

	return NULL;
}

static int
sp_priv_ismember(Spuserpool *up, Spuser *u, Spgroup *g)
{
	int i;
	for(i = 0; i < u->ngroups; i++)
		if (u->groups[i] == g)
			return 1;

	return 0;
}

static void
sp_priv_udestroy(Spuserpool *up, Spuser *u)
{
}

static void
sp_priv_gdestroy(Spuserpool *up, Spgroup *g)
{
}

