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
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <signal.h>
#include <regex.h>
#include <math.h>

#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "xcpu.h"
#include "libxauth.h"
#include "libxcpu.h"
#include "xcpuimpl.h"

Xpsessionset *
xp_sessionset_alloc(int n)
{
	Xpsessionset *ss;

	ss = sp_malloc(sizeof(*ss));
	if (!ss)
		return NULL;

	ss->len = 0;
	ss->size = n;
	ss->sessions = sp_malloc(ss->size * sizeof(Xpsession *));
	if (!ss->sessions) {
		free(ss);
		return NULL;
	}

	memset(ss->sessions, 0, ss->size * sizeof(Xpsession *));
	return ss;
}

Xpsessionset *
xp_sessionset_create(Xpnodeset *nds, Xpcommand *cm)
{
	int i, ecode;
	char *ename;
	Xpsessionset *ss;

	ss = xp_sessionset_alloc(nds->len);
	if (!ss)
		return NULL;

	for(i = 0; i < ss->size; i++) {
		ss->sessions[i] = xp_session_create(&nds->nodes[i], 
			cm->user, cm->userkey);
		if (!ss->sessions[i])
			goto error;

		ss->sessions[i]->command = cm;
		ss->len++;
	}

	return ss;

error:
	sp_rerror(&ename, &ecode);
	ename = ename?strdup(ename):NULL;
	for(i = 0; i < ss->len; i++)
		xp_session_destroy(ss->sessions[i]);

	free(ss->sessions);
	free(ss);
	sp_werror(ename, ecode);
	free(ename);
	return NULL;
}

void
xp_sessionset_destroy(Xpsessionset *ss)
{
	int i;

	for(i = 0; i < ss->len; i++) 
		xp_session_destroy(ss->sessions[i]);

	free(ss->sessions);
	free(ss);
}

Xpsessionset *
xp_sessionset_by_jobid(Xpnodeset *nds, char *jobid, Xpcommand *cm)
{
	int i, m, n, l, len;
	int ecode;
	char *ename;
	Xpsessionset *ss;
	Xpproc *procs, *xp;

	ss = NULL;
	n = xp_proc_list(nds, cm->user, cm->userkey, &procs);
	if (n < 0)
		return NULL;

	len = strlen(jobid);
	/* firgure out the number of xcpu sessions for the job id */
	/* count the number of processes that have the jobid set, and their parents don't */
	for(m = 0, i = 0; i < n; i++) {
		xp = &procs[i];

		if (xp->xcpujid && xp->parent && !xp->parent->xcpujid) {
			l = strlen(xp->xcpujid);
			if (l <= len)
				continue;

			if (memcmp(xp->xcpujid, jobid, len)==0 && xp->xcpujid[len]=='/')
				m++;
		}
	}

	if (!m) {
		sp_werror("no sessions found", EIO);
		goto error;
	}

	ss = xp_sessionset_alloc(m);
	if (!ss)
		goto error;

	for(i=0; i < n; i++) {
		xp = &procs[i];
		
		if (xp->xcpujid && xp->parent && !xp->parent->xcpujid) {
			l = strlen(xp->xcpujid);
			if (l <= len)
				continue;

			if (memcmp(xp->xcpujid, jobid, len)==0 && xp->xcpujid[len]=='/') {
				ss->sessions[ss->len] = xp_session_attach(xp->node, 
					xp->xcpusid, cm->user, cm->userkey);
				if (!ss->sessions[ss->len])
					goto error;

				ss->sessions[ss->len]->command = cm;
				ss->len++;
			}
		}
	}

	free(procs);
	return ss;

error:
	sp_rerror(&ename, &ecode);
	ename = ename?strdup(ename):NULL;
	if (ss)
		xp_sessionset_destroy(ss);
	free(procs);
	sp_werror(ename, ecode);
	free(ename);
	return NULL;
}

static Xpsession *
xp_session_alloc()
{
	Xpsession *ss;

	ss = sp_malloc(sizeof(*ss));
	if (!ss)
		return NULL;

	ss->node = NULL;
	ss->sid = NULL;
	ss->jid = NULL;
	ss->command = NULL;
	ss->ename = NULL;
	ss->ecode = 0;
	ss->exitcode = NULL;
	ss->ctl = NULL;
	ss->wait = NULL;
	ss->in = NULL;
	ss->out = NULL;
	ss->err = NULL;
	ss->wspcfd = NULL;
	ss->ispcfd = NULL;
	ss->ospcfd = NULL;
	ss->espcfd = NULL;
	ss->inbuf = NULL;
	ss->insize = 0;
	ss->inpos = 0;
	ss->closein = 0;
	ss->outpos = 0;
	ss->errpos = 0;
	ss->files = NULL;
	ss->copyf = NULL;
	ss->pkfid = 0;

	return ss;
}

Xpsession *
xp_session_create(Xpnode *nd, Spuser *user, Xkey *ukey)
{
	int n;
	char buf[64];
	Spcfid *fid;
	Xpsession *ss;

	fid = NULL;
	ss = xp_session_alloc();
	if (!ss)
		return NULL;

	ss->node = nd;
	ss->user = user;
	ss->ukey = ukey;
	ss->fs = xp_node_mount(nd, user, ukey);
	if (!ss->fs)
		goto error;

	fid = spc_open(ss->fs, "arch", Oread);
	if (!fid)
		goto error;

	n = spc_read(fid, (u8 *) buf, sizeof(buf) - 1, 0);
	if (n < 0)
		goto error;
	if (n == 0) {
		sp_werror("error while reading arch", EIO);
		goto error;
	}

	spc_close(fid);
	buf[n] = '\0';
	nd->arch = strdup(buf);
	if (!nd->arch) {
		sp_werror(Enomem, ENOMEM);
		goto error;
	}

	fid = spc_open(ss->fs, "clone", Oread);
	if (!fid)
		goto error;

	n = spc_read(fid, (u8 *) buf, sizeof(buf) - 1, 0);
	if (n <= 0) {
		sp_werror("error while reading clone", EIO);
		goto error;
	}

	buf[n] = '\0';
	ss->sid = strdup(buf);

	snprintf(buf, sizeof(buf), "%s/ctl", ss->sid);
	ss->ctl = spc_open(ss->fs, buf, Owrite);
	if (!ss->ctl)
		goto error;

	snprintf(buf, sizeof(buf), "%s/wait", ss->sid);
	ss->wait = spc_open(ss->fs, buf, Oread);
	if (!ss->wait)
		goto error;

	snprintf(buf, sizeof(buf), "%s/stdin", ss->sid);
	ss->in = spc_open(ss->fs, buf, Owrite);
	if (!ss->in)
		goto error;

	snprintf(buf, sizeof(buf), "%s/stdout", ss->sid);
	ss->out = spc_open(ss->fs, buf, Oread);
	if (!ss->out)
		goto error;

	snprintf(buf, sizeof(buf), "%s/stderr", ss->sid);
	ss->err = spc_open(ss->fs, buf, Oread);
	if (!ss->err)
		goto error;

	spc_close(fid);

	return ss;

error:
	if (ss->ctl)
		spc_close(ss->ctl);
	if (ss->wait)
		spc_close(ss->wait);
	if (ss->in)
		spc_close(ss->in);
	if (ss->out)
		spc_close(ss->out);
	if (ss->err)
		spc_close(ss->err);
	if (fid)
		spc_close(fid);
	if (ss->fs)
		spc_umount(ss->fs);
	free(ss->sid);
	free(ss);

	return NULL;
}

void
xp_session_destroy(Xpsession *ss)
{
	if (ss->copyf)
		xp_file_copy_finish(ss->copyf);
	if (ss->files)
		xp_file_destroy_all(ss->files);
	free(ss->inbuf);
	if (ss->wspcfd)
		spcfd_remove(ss->wspcfd);
	if (ss->ispcfd)
		spcfd_remove(ss->ispcfd);
	if (ss->ospcfd)
		spcfd_remove(ss->ospcfd);
	if (ss->espcfd)
		spcfd_remove(ss->espcfd);
	if (ss->ctl)
		spc_close(ss->ctl);
	if (ss->wait)
		spc_close(ss->wait);
	if (ss->in)
		spc_close(ss->in);
	if (ss->out)
		spc_close(ss->out);
	if (ss->err)
		spc_close(ss->err);
	if (ss->pkfid)
		spc_close(ss->pkfid);

	if (ss->fs) {
		spc_umount(ss->fs);
		ss->fs = NULL;
	}
	free(ss->sid);
	free(ss);
}

Xpsession*
xp_session_attach(Xpnode *nd, char *sid, Spuser *user, Xkey *key)
{
	char buf[64];
	Spcfid *fid;
	Xpsession *ss;

	fid = NULL;
	ss = xp_session_alloc();
	if (!ss)
		return NULL;

	ss->node = nd;
	ss->sid = strdup(sid);
	ss->fs = xp_node_mount(nd, user, key);
	if (!ss->fs)
		goto error;

	snprintf(buf, sizeof(buf), "%s/ctl", ss->sid);
	ss->ctl = spc_open(ss->fs, buf, Owrite);
	if (!ss->ctl)
		goto error;

	snprintf(buf, sizeof(buf), "%s/wait", ss->sid);
	ss->wait = spc_open(ss->fs, buf, Oread);
	if (!ss->wait)
		goto error;

	snprintf(buf, sizeof(buf), "%s/stdin", ss->sid);
	ss->in = spc_open(ss->fs, buf, Owrite);
	if (!ss->in)
		goto error;

	snprintf(buf, sizeof(buf), "%s/stdout", ss->sid);
	ss->out = spc_open(ss->fs, buf, Oread);
	if (!ss->out)
		goto error;

	snprintf(buf, sizeof(buf), "%s/stderr", ss->sid);
	ss->err = spc_open(ss->fs, buf, Oread);
	if (!ss->err)
		goto error;

	return ss;

error:
	if (ss->ctl)
		spc_close(ss->ctl);
	if (ss->wait)
		spc_close(ss->wait);
	if (ss->in)
		spc_close(ss->in);
	if (ss->out)
		spc_close(ss->out);
	if (ss->err)
		spc_close(ss->err);
	if (ss->fs)
		spc_umount(ss->fs);
	free(ss->sid);
	free(ss);

	return NULL;
}

int
xp_session_setup_start(Xpsession *ss, char *env, char *ns, char *argv, char *ctl)
{
	int n;
	char buf[1024];

	if (env) {
		snprintf(buf, sizeof(buf), "%s/env", ss->sid);
		n = xp_file_create_from_buf(&ss->files, ss->fs, buf,
			strdup(env), strlen(env));
		if (n < 0)
			goto error;
	}

	if (argv) {
		snprintf(buf, sizeof(buf), "%s/argv", ss->sid);
		n = xp_file_create_from_buf(&ss->files, ss->fs, buf,
			strdup(argv), strlen(argv));
		if (n < 0)
			goto error;
	}

	if (ns) {
		snprintf(buf, sizeof(buf), "%s/ns", ss->sid);
		n = xp_file_create_from_buf(&ss->files, ss->fs, buf,
			strdup(ns), strlen(ns));
		if (n < 0)
			goto error;
	}

	if (ctl) {
		snprintf(buf, sizeof(buf), "%s/ctl", ss->sid);
		n = xp_file_create_from_buf(&ss->files, ss->fs, buf,
			strdup(ctl), strlen(ctl));
		if (n < 0)
			goto error;
	}

	if (ss->files) {
		ss->copyf = xp_file_copy_start(ss->files);
		if (!ss->copyf)
			goto error;
	}

	return 0;

error:
	return -1;
}

int
xp_session_setup_finish(Xpsession *ss)
{
	xp_file_copy_finish(ss->copyf);
	ss->copyf = NULL;
	xp_file_destroy_all(ss->files);
	ss->files = NULL;

	return 0;
}

Xpnode *
xp_session_get_node(Xpsession *s)
{
	return s->node;
}

char *
xp_session_get_id(Xpsession *s)
{
	return s->sid;
}

int xp_session_get_localaddr(Xpsession *s, char *buf, int buflen)
{
	if (s->fs)
		return spc_getladdr(s->fs, buf, buflen);
	else
		return -1;
}

int
xp_session_close_stdin(Xpsession *s)
{
	int n;
	char *buf;

	if (s->inpos) {
		s->closein = 1;
		return 0;
	}

	buf = "close stdin\n";
	n = spc_write(s->ctl, (u8 *) buf, strlen(buf), 0);
	if (n < 0)
		goto error;
	else if (n == 0 || n != strlen(buf)) {
		sp_werror("error while writing", EIO);
		goto error;
	}

	return 0;

error:
	return -1;
}

static int
xp_session_cmp_arch(const void *a1, const void *a2)
{
	const Xpsession *s1, *s2;
	const Xpnode *n1, *n2;

	s1 = a1;
	s2 = a2;
	n1 = s1->node;
	n2 = s2->node;

	if (n1->arch && !n2->arch)
		return 1;
	else if (!n1->arch && n2->arch)
		return -1;
	else if (!n1->arch && !n2->arch)
		return 0;
	else
		return strcmp(n1->arch, n2->arch);
}

int
xp_sessionset_split_by_arch(Xpsessionset *ss, Xpsessionset ***ssa)
{
	int i, j, m, n;
	char *arch;
	Xpsessionset **ret;

	if (ss->len == 0) {
		sp_werror("no nodes", EIO);
		return -1;
	}

	qsort(ss->sessions, ss->len, sizeof(Xpsession *), &xp_session_cmp_arch);
	arch = NULL;
	for(n = 0, i = 0; i < ss->len; i++) {
		if (!arch || strcmp(ss->sessions[i]->node->arch, arch) != 0) {
			arch = ss->sessions[i]->node->arch;
			n++;
		}
	}

	ret = sp_malloc(n * sizeof(Xpsessionset *));
	if (!ret)
		return -1;

	memset(ret, 0, n * sizeof(Xpsessionset *));
	arch = NULL;
	for(n = -1, m = 0, i = 0; i < ss->len; i++) {
		if (!arch || strcmp(ss->sessions[i]->node->arch, arch) != 0) {
			if (i-m > 0) {
				n++;
				ret[n] = xp_sessionset_alloc(i - m);
				ret[n]->len = i - m;
				for(j = m; j < i; j++)
					ret[n]->sessions[j-m] = ss->sessions[j];
			}

			arch = ss->sessions[i]->node->arch;
			m = i;
		}
	}

	if (i-m > 0) {
		n++;
		ret[n] = xp_sessionset_alloc(i - m);
		ret[n]->len = i - m;
		for(j = m; j < i; j++)
			ret[n]->sessions[j-m] = ss->sessions[j];
	}

	ss->len = 0;	/* we copied the sessions to other sessionsets */
	*ssa = ret;
	return n+1;
}

int
xp_session_get_passkey(Xpsession *ss, char *pk, int pklen)
{
	int n;
	char buf[4096];

	if (!ss->pkfid) {
		ss->pkfid = spc_open(ss->fs, "passkey", Oread);
		if (!ss->pkfid)
			return -1;
	}

	n = spc_read(ss->pkfid, (u8 *) buf, sizeof(buf) - 1, 0);
	if (n < 0)
		return -1;

	n = xauth_privkey_decrypt(buf, n, pk, pklen - 1, ss->ukey);
	if (n < 0)
		return -1;

	pk[n] = 0;
	return 0;
}
