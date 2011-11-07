//#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <signal.h>
#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "xcpu.h"
#include "libxauth.h"
#include "xcpufs.h"

typedef struct Passkey Passkey;
typedef struct Xauth Xauth;

struct Passkey {
	int		refcount;
	Spuser*		user;
	u8		passkey[64];

	Passkey*	next;
};

enum {
	Authstart,
	Authread,
	Authfail,
};

struct Xauth {
	char		authid[16];
	Spuser*		user;
	char		response[4096];
	int		resplen;
};

static Passkey* passkeys;

int
ukey_add(Spuserpool *up, char *uname, u32 uid, char *dfltgname, 
	char *key, int keylen)
{
	Spuser *user;
	Spgroup *dgrp;
	Xkey *xkey;

	xkey = NULL;
	if (key) {
		xkey = xauth_pubkey_create(key, keylen);
		if (!xkey)
			return -1;
	}

	user = sp_priv_user_add(up, uname, uid, xkey);
	if (!user) {
		if (xkey)
			xauth_destroy(xkey);
		return -1;
	}

	if (dfltgname) {
		dgrp = up->gname2group(up, dfltgname);
		if (!dgrp) {
			sp_werror("%s:%s", EIO, dfltgname, "group not found");
			sp_priv_user_del(user);
			sp_user_decref(user);
			xauth_destroy(xkey);
			return -1;
		}

		sp_priv_group_adduser(dgrp, user);
		sp_priv_user_setdfltgroup(user, dgrp);
	}

	return 0;
}

int
ukey_del(Spuserpool *up, char *uname)
{
	Spuser *user;
	int i;

	user = up->uname2user(up, uname);
	if (user) {
		for(i=0; i < user->ngroups; i++)
			sp_priv_group_deluser(user->groups[i], user);

		sp_priv_user_del(user);
		sp_user_decref(user);
		return 0;
	} else {
		sp_werror("%s: no such user in userpool", EIO, uname);
		return -1;
	}
}

int
ukey_flush(Spuserpool *up)
{
	Spuser *user;
	int i;

	user = sp_priv_user_list(up);
	if (user) {
		while (user != NULL) {
			if (strcmp("xcpu-admin", user->uname)) {
				for(i=0; i < user->ngroups; i++)
					sp_priv_group_deluser(user->groups[i], user);

				sp_priv_user_del(user);
				sp_user_decref(user);
			}
			user = user->next;
		}
	}
	return 0;
}

int
ukey_add_group(Spuserpool *up, char *uname, char *gname)
{
	Spuser *user;
	Spgroup *group;

	user = up->uname2user(up, uname);
	if (!user) {
		sp_werror("%s: no such user in userpool", EIO, uname);
		return -1;
	}

	group = up->gname2group(up, gname);
	if (!group) {
		sp_werror("%s: no such group in userpool", EIO, gname);
		return -1;
	}
	return sp_priv_group_adduser(group, user);
}

int
ukey_del_group(Spuserpool *up, char *uname, char *gname)
{
	Spuser *user;
	Spgroup *group;

	user = up->uname2user(up, uname);
	if (!user) {
		sp_werror("%s: no such user in userpool", EIO, uname);
		return -1;
	}

	group = up->gname2group(up, gname);
	if (!group) {
		sp_werror("%s: no such group in userpool", EIO, gname);
		return -1;
	}

	if (!user->upool->ismember(user->upool, user, group)) {
		sp_werror("user %s not a member of group %s", EIO,
			  uname, gname);
		return -1;
	}		
	return sp_priv_group_deluser(group, user);
}

int
group_add(Spuserpool *up, char *groupname, u32 gid)
{
	Spgroup *g;

	g = sp_priv_group_add(up, groupname, gid);
	if (!g) {
		return -1;
	}

	return 0;
}

int
group_del(Spuserpool *up, char *groupname)
{
	Spgroup *g;

	g = up->gname2group(up, groupname);
	if (!g) {
		sp_werror("%s: no such group in userpool", EIO, groupname);
		return -1;
	} else {
		sp_priv_group_del(g);
		return 0;
	}
}

int
group_flush(Spuserpool *up)
{
	Spgroup *group;

	ukey_flush(up);
	group = sp_priv_group_list(up);
	if (group) {
		while (group != NULL) {
			if (strcmp("xcpu-admin", group->gname)) {
				sp_priv_group_del(group);
				sp_group_decref(group);
			}
			group = group->next;
		}
	}
	return 0;
}

int
pkey_gen(Spuser *user, char *buf, int buflen)
{
	int i;
	char b[16];
	Xkey *key;
	Passkey *p;

	key = user->aux;
	p = sp_malloc(sizeof(*p));
	if (!p)
		return -1;

	sp_user_incref(user);
	p->user = user;
	xauth_rand((u8 *) b, sizeof(b));
	for(i = 0; i < sizeof(b); i++)
		sprintf((char *) &p->passkey[i*2], "%02x", b[i]);
	p->next = passkeys;
	passkeys = p;

	return xauth_pubkey_encrypt(p->passkey, sizeof(b)*2, (u8 *) buf, buflen, key);
}

int
xauth_startauth(Spfid *afid, char *aname, Spqid *aqid)
{
	Xauth *auth;

	auth = sp_malloc(sizeof(*auth));
	if (!auth)
		return 0;

	sp_user_incref(afid->user);
	auth->user = afid->user;
	xauth_rand((u8 *) auth->authid, sizeof(auth->authid));
//	snprintf(auth->authid, sizeof(auth->authid), "%d", nextid);
	auth->resplen = 0;
	memset(auth->response, 0, sizeof(auth->response));
	afid->aux = auth;
	aqid->type = Qtauth;
	aqid->version = 0;
	aqid->path = 0;

	return 1;
}

int
xauth_checkauth(Spfid *fid, Spfid *afid, char *aname)
{
	int n;
	char buf[4096], hash[4096];
	Xauth *auth;
	Xkey *ukey;
	Passkey *p, *pp;

	if(!afid) {
		if (fid->user && !fid->user->aux)
			return 1;

		goto error;
	}

	auth = afid->aux;
	if (!auth)
		goto error;

	if (fid->user != afid->user)
		goto error;

	ukey = auth->user->aux;

	/* if the user doesn't have a key, authentication succeeds */
	if (!ukey)
		return 1;

	/* if ukey is ~0, authentication always fails */
	if (ukey == (Xkey *) ~0)
		goto error;

	/* check if the response is signed with user's public key */
	if (xauth_verify((u8 *) auth->authid, sizeof(auth->authid), 
		(u8 *) auth->response, auth->resplen, ukey))
		return 1;

	/* then check if there is a passkey which hash is sent in the response */
	for(pp=NULL, p=passkeys; p != NULL; pp=p, p=p->next) {
		if (p->user==auth->user) {
			memmove(buf, auth->authid, sizeof(auth->authid));
			memmove(buf + sizeof(auth->authid), p->passkey, 
				strlen((char *) p->passkey) + 1);
			n = xauth_hash((u8 *) buf, strlen(buf), (u8 *) hash, sizeof(hash));
			if (n < 0)
				goto error;

			if (n!=auth->resplen && !memcmp(hash, auth->response, n))
				continue;
				
			if (pp)
				pp->next = p->next;
			else
				passkeys = p->next;

			free(p);
			return 1;
		}
	}

	/* and the last case -- signed by the administrator */
	if (xauth_verify((u8 *) auth->authid, sizeof(auth->authid), 
		(u8 *) auth->response, auth->resplen, adminkey))
		return 1;

error:
	sp_werror("authentication failed", EIO);
	return 0;
}

int
xauth_read(Spfid *fid, u64 offset, u32 count, u8 *data)
{
	int n;
	Xauth *auth;

	n = 0;
	auth = fid->aux;
	if (!auth) {
		sp_werror("authentication failed", EIO);
		return -1;
	}

	n = cutbuf(data, offset, count, auth->authid, 0, sizeof(auth->authid));
	return n;
}

int
xauth_write(Spfid *fid, u64 offset, u32 count, u8 *data)
{
	Xauth *auth;

	auth = fid->aux;
	if (!auth) {
		sp_werror("authentication failed", EIO);
		return -1;
	}

	if (offset+count > sizeof(auth->response)) {
		sp_werror("invalid size", EIO);
		return -1;
	}

	if (count <= 0)
		return 0;

	memmove(auth->response + offset, data, count);
	if (offset+count > auth->resplen)
		auth->resplen = offset + count;

	return count;
}

int
xauth_clunk(Spfid *fid)
{
	Xauth *auth;

	auth = fid->aux;
	if (!auth)
		return 1;

	sp_user_decref(auth->user);
	free(auth);
	fid->aux = NULL;
	return 1;
}
