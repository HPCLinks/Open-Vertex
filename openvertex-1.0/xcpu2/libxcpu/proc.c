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

static int xp_proc_list_node(Xpnode *nd, Spuser *user, Xkey *key, Xpproc **ret);
static int xp_proc_parse(char *p, Xpproc *xp);

int
xp_proc_list(Xpnodeset *nds, Spuser *user, Xkey *key, Xpproc **xps)
{
	int i, n, nlen;
	Xpproc *ps, *ret, *t;

	ret = NULL;
	nlen = 0;
	for(i = 0; i < nds->len; i++) {
		n = xp_proc_list_node(&nds->nodes[i], user, key, &ps);
		if (n > 0) {
			t = realloc(ret, (n+nlen) * sizeof(Xpproc));
			if (!t) {
				sp_werror(Enomem, ENOMEM);
				free(ps);
				free(ret);
				return -1;
			}

			ret = t;
			memmove(ret + nlen, ps, n * sizeof(Xpproc));
			nlen += n;
			free(ps);
		}
	}

	*xps = ret;
	return nlen;
}

int
xp_proc_kill(Xpproc *xp, Spuser *user, Xkey *ukey, int signo)
{
	int n;
	char buf[32];
	Spcfsys *fs = NULL;
	Spcfid *fid = NULL;
	char *ctl = NULL;

	fs = xp_node_mount(xp->node, user, ukey);
	if (!fs) 
		goto error;

	fid = spc_open(fs, "ctl", Owrite);
	if (!fid) {
		if (!xp->xcpusid)
			goto error;

		n = strlen(xp->xcpusid) + 5;
		ctl = sp_malloc(n);
		snprintf(ctl, n, "%s/ctl", xp->xcpusid);
		fid = spc_open(fs, ctl, Owrite);
		if (!fid)
			goto error;
	}

	if (!ctl)
		snprintf(buf, sizeof(buf), "kill %d %d\n", signo, xp->pid);
	else
		snprintf(buf, sizeof(buf), "signal %d\n", signo);

	n = spc_write(fid, (u8 *) buf, strlen(buf), 0);
	if (n != strlen(buf) || n <= 0)
		goto error;

	spc_close(fid);
	spc_umount(fs);
	free(ctl);
	return 0;
error:
	if (fid)
		spc_close(fid);
	if (fs)
		spc_umount(fs);	

	sp_werror("%s: error killing process %d", EIO, xp->node->name, xp->pid);
	free(ctl);	
	return -1;
}

static int
xp_proc_list_node(Xpnode *nd, Spuser *user, Xkey *key, Xpproc **ret)
{
	int i, j, n, m, nxps, szxps, first;
	u64 l;
	char buf[16384], *p;
	Spcfsys *fs;
	Spcfid *fid;
	Xpproc *xps, *t;

	xps = NULL;
	nxps = 0;
	szxps = 0;
	if (!user) 
		return -1;

	fs = xp_node_mount(nd, user, key);
	if (!fs) 
		return -1;

	fid = spc_open(fs, "procs", Oread);
	if (!fid) {
		spc_umount(fs);
		return -1;
	}

	n = 0;
	l = 0;
	first = 1;
	while ((i = spc_read(fid, (u8 *) buf + n, sizeof(buf) - n, l)) > 0) {
		n += i;
		l += i;

		m = 0;
		while (m<n && (p = memchr(buf + m, '\n', n - m))!=NULL) {
			*p = '\0';

			/* skip the first line */
			if (first) {
				first = 0;
				m += (p - (buf+m)) + 1;
				continue;
			}

			if (nxps >= szxps) {
				szxps += 32;
				t = realloc(xps, szxps * sizeof(Xpproc));
				if (!t) {
					sp_werror(Enomem, ENOMEM);
					goto error;
				}

				xps = t;
			}

			if (xp_proc_parse(buf + m, &xps[nxps]) < 0) 
				goto error;

			xps[nxps].node = nd;
			m += (p - (buf+m)) + 1;
			nxps++;
		}

		if (m != n) 
			memmove(buf, buf+m, n-m);
		n -= m;
	}

	if (i < 0) 
		goto error;

	spc_close(fid);
	spc_umount(fs);

	/* setup the parent field in the Xpprocs */
	for(i = 0; i < nxps; i++) {
		for(j = 0; j < nxps; j++)
			if (xps[i].ppid == xps[j].pid) {
				xps[i].parent = &xps[j];
				break;
			}
	}

	*ret = xps;
	return nxps;

error:
	free(xps);
	spc_close(fid);
	spc_umount(fs);
	return -1;
}

static int
xp_proc_parse(char *p, Xpproc *xp)
{
	int n;
	u64 st;
	char *s, *t, **toks;

	n = strlen(p) - 1;
	while (p[n] == ' ' || p[n] == '\t') n--;

	if (p[0] != '(' || p[n] != ')')
		goto error;

	p[n] = '\0';
	/* parse pid */
	xp->pid = strtol(p+1, &s, 10);
	if (*s != ' ')
		goto error;

	/* parse cmdline */
	s++;
	if (*s != '(')
		goto error;

	t = strrchr(s, ')');
	if (!t)
		goto error;

	*t = '\0';
	xp->cmdline = strdup(s + 1);

	n = tokenize(t+1, &toks);
	if (n != 25)
		goto error;

	switch (toks[0][0]) {
	case 'R':
		xp->state = Running;
		break;
	case 'S':
		xp->state = Sleeping;
		break;
	case 'Z':
		xp->state = Zombie;
		break;
	case 'W':
		xp->state = Paging;
		break;
	case 'D':
		xp->state = Waiting;
		break;
	case 'T':
		xp->state = Stopped;
		break;
	default:
		xp->state = Unknown;
	}

	xp->ppid = strtol(toks[1], &s, 10);
	if (*s != '\0')
		goto error;
	xp->parent = NULL;

	xp->pgrp = strtol(toks[2], &s, 10);
	if (*s != '\0')
		goto error;

	xp->psid = strtol(toks[3], &s, 10);
	if (*s != '\0')
		goto error;

	xp->tty = strdup(toks[4]);
	xp->tpgid = strtol(toks[5], &s, 10);
	if (*s != '\0')
		goto error;

	xp->utime = strtoll(toks[6], &s, 10);
	if (*s != '\0')
		goto error;

	xp->stime = strtoll(toks[7], &s, 10);
	if (*s != '\0')
		goto error;

	st = strtoll(toks[8], &s, 10);
	if (*s != '\0')
		goto error;

	xp->starttime.tv_sec = st / 1000;
	xp->starttime.tv_usec = (st - xp->starttime.tv_sec) * 1000;

	xp->priority = strtol(toks[9], &s, 10);
	if (*s != '\0')
		goto error;

	xp->nice = strtol(toks[10], &s, 10);
	if (*s != '\0')
		goto error;

	xp->wchan = strdup(toks[11]);

	xp->euid = strtol(toks[12], &s, 10);
	if (*s != '\0')
		goto error;

	xp->suid = strtol(toks[13], &s, 10);
	if (*s != '\0')
		goto error;

	xp->fsuid = strtol(toks[14], &s, 10);
	if (*s != '\0')
		goto error;

	xp->egid = strtol(toks[15], &s, 10);
	if (*s != '\0')
		goto error;

	xp->sgid = strtol(toks[16], &s, 10);
	if (*s != '\0')
		goto error;

	xp->fsgid = strtol(toks[17], &s, 10);
	if (*s != '\0')
		goto error;

	xp->vmsize = strtoll(toks[18], &s, 10);
	if (*s != '\0')
		goto error;

	xp->rssize = strtoll(toks[19], &s, 10);
	if (*s != '\0')
		goto error;

	xp->shsize = strtoll(toks[20], &s, 10);
	if (*s != '\0')
		goto error;

	xp->txtsize = strtoll(toks[21], &s, 10);
	if (*s != '\0')
		goto error;

	xp->datsize = strtoll(toks[22], &s, 10);
	if (*s != '\0')
		goto error;

	if (strlen(toks[23]) > 0)
		xp->xcpusid = strdup(toks[23]);
	else
		xp->xcpusid = NULL;

	if (strlen(toks[24]) > 0)
		xp->xcpujid = strdup(toks[24]);
	else
		xp->xcpujid = NULL;

	return 0;

error:
	sp_werror("syntax error", EIO);
	return -1;
}
