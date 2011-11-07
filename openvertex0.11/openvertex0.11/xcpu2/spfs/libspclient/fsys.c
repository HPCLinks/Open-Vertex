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
#include <sys/socket.h>
#include <assert.h>
#include "spfs.h"
#include "spclient.h"
#include "spcimpl.h"

typedef struct Spcrpc Spcrpc;
struct Spcrpc {
	Spcfsys*	fs;
	Spfcall*	tc;
	Spfcall*	rc;
	char*		ename;
	int		ecode;
};

int spc_chatty;
int spc_msize = 32768 + IOHDRSZ;
char *Econn = "connection closed";
static char *Emismatch = "response mismatch";
static char *Eflush = "request flushed";

static Spfcall *spc_fcall_alloc(u32 msize);
static void spc_notify(Spfd *spfd, void *aux);

Spcfsys *
spc_create_fsys(int fd, int msize)
{
	Spcfsys *fs;

	fs = sp_malloc(sizeof(*fs));
	if (!fs)
		return NULL;

	fs->fd = fd;
	fs->spfd = NULL;
	fs->dotu = 0;
	fs->msize = msize;
	fs->root = NULL;
	fs->afid = NULL;
	fs->tagpool = NULL;
	fs->fidpool = NULL;
	fs->ifcall = NULL;
	fs->pend_pos = 0;
	fs->pend_first = NULL;
	fs->pend_last = NULL;
	fs->sent_reqs = NULL;
	fs->ename = NULL;
	fs->ecode = 0;
	fs->in_notify = 0;
	fs->destroyed = 0;
	fs->laddr = NULL;
	fs->raddr = NULL;

	fs->spfd = spfd_add(fd, spc_notify, fs);
	if (!fs->spfd)
		goto error;

	fs->tagpool = spc_create_pool(NOTAG);
	if (!fs->tagpool)
		goto error;
		
	fs->fidpool = spc_create_pool(NOFID);
	if (!fs->fidpool)
		goto error;

	return fs;

error:
	spc_disconnect_fsys(fs);
	return NULL;
}

void 
spc_remount(Spcfsys *fs)
{
	fs->spfd = spfd_add(fs->fd, spc_notify, fs);
}

void
spc_disconnect_fsys(Spcfsys *fs)
{
	int ecode;
	char *ename;
	Spcreq *req, *req1;

	sp_rerror(&fs->ename, &fs->ecode);
	if (fs->ecode) {
		fs->ename = strdup(fs->ename);
		if (!fs->ename) 
			fs->ename = Enomem;
	}

	if (fs->root) {
		spc_fid_free(fs->root);
		fs->root = NULL;
	}

	if (fs->afid) {
		spc_fid_free(fs->afid);
		fs->afid = NULL;
	}

	if (fs->fd >= 0) {
		shutdown(fs->fd, 2);
		close(fs->fd);
		fs->fd = -1;
	}

	if (fs->spfd) {
		spfd_remove(fs->spfd);
		fs->spfd = NULL;
	}

	sp_rerror(&ename, &ecode);
	if (ecode) {
		ename = strdup(ename);
		if (!ename) {
			ename = Enomem;
			ecode = ENOMEM;
		}
	}

	sp_werror(Econn, ECONNRESET);
	req = fs->pend_first;
	while (req != NULL) {
		(*req->cb)(req->cba, NULL);
		req1 = req->next;
		free(req);
		req = req1;
	}
	fs->pend_first = NULL;

	req = fs->sent_reqs;
	while (req != NULL) {
		(*req->cb)(req->cba, NULL);
		req1 = req->next;
		free(req);
		req = req1;
	}
	fs->sent_reqs = NULL;

	sp_werror(ename, ecode);
	if (ename != Enomem)
		free(ename);
}

void
spc_destroy_fsys(Spcfsys *fs)
{
	assert(fs->fd<0);
	if (fs->tagpool) {
		spc_destroy_pool(fs->tagpool);
		fs->tagpool = NULL;
	}

	if (fs->fidpool) {
		spc_destroy_pool(fs->fidpool);
		fs->fidpool = NULL;
	}

	free(fs->ifcall);
	if (fs->ename != Enomem)
		free(fs->ename);

	free(fs->raddr);
	fs->raddr = NULL;
	free(fs->laddr);
	fs->laddr = NULL;
	if (fs->in_notify)
		fs->destroyed = 1;
	else
		free(fs);
}

void
spc_request_flushed(Spcreq *r)
{
	int ecode;
	char *ename;
	Spcreq *req, *preq;
	Spcfsys *fs;

	fs = r->fs;
	for(preq=NULL, req = fs->sent_reqs; req != NULL; preq=req, req = req->next)
		if (r == req)
			break;

	if (req) {
		if (preq)
			preq->next = req->next;
		else
			fs->sent_reqs = req->next;

		sp_rerror(&ename, &ecode);
		if (ename)
			ename = strdup(ename);

		sp_werror(Eflush, EIO);
		(*req->cb)(req->cba, NULL);
		sp_werror(ename, ecode);
		free(ename);
	}

	/* if req->flushed is set, the request is not freed if response arrives */
	spc_put_id(fs->tagpool, r->tag);
	free(r);
}

void
spc_flush_cb(void *aux, Spfcall *rc)
{
	free(rc);
	spc_request_flushed((Spcreq *) aux);
}

static void
spc_flush_request(Spcreq *req)
{
	Spfcall *fc;
	Spcfsys *fs;

	if (req->flushed)
		return;

	req->flushed = 1;
	fs = req->fs;
	fc = sp_create_tflush(req->tag);
	if (sp_poll_looping()) 
		spc_rpcnb(fs, fc, spc_flush_cb, req);
	else {
		spc_rpc(fs, fc, NULL);
		spc_request_flushed(req);
	}
}

void
spc_flush_requests(Spcfsys *fs, Spcfid *fid)
{
	int ecode;
	char *ename;
	Spcreq *preq, *req, *req1;

	if (fs->fd < 0)
		return;

	// check the unsent requests
	sp_rerror(&ename, &ecode);
	if (ename)
		ename = strdup(ename);

	sp_werror(Eflush, EIO);
	preq = NULL;
	req = fs->pend_first;
	while (req != NULL) {
		if (req->tc->fid == fid->fid) {
			if (preq)
				preq->next = req->next;
			else
				fs->pend_first = req->next;

			if (req == fs->pend_last)
				fs->pend_last = preq;

			(*req->cb)(req->cba, NULL);
			req1 = req->next;
			free(req);
			req = req1;
		} else {
			preq = req;
			req = req->next;
		}
	}

	// check the sent ones
	req = fs->sent_reqs;
	while (req != NULL) {
		if (req->tc->fid == fid->fid && !req->flushed) {
			spc_flush_request(req);
			req = fs->sent_reqs;
		} else {
			req = req->next;
		}
	}
	sp_werror(ename, ecode);
	free(ename);
}

static void
spc_fd_read(Spcfsys *fs)
{
	int n, size;
	Spfcall *fc;
	Spcreq *req, *preq;

	if (!fs->ifcall) {
		fs->ifcall = spc_fcall_alloc(fs->msize);
		if (!fs->ifcall) {
			spc_disconnect_fsys(fs);
			return;
		}

		fs->ifcall->size = 0;
	}

	fc = fs->ifcall;
	n = spfd_read(fs->spfd, fc->pkt + fc->size, fs->msize - fc->size);
	if (n <= 0) {
		if (n == 0)
			spc_disconnect_fsys(fs);
		return;
	}

	fc->size += n;

again:
	if (fc->size < 4)
		return;

	n = fc->size;
	size = fc->pkt[0] | (fc->pkt[1]<<8) | (fc->pkt[2]<<16) | (fc->pkt[3]<<24);
	if (size > fs->msize) {
		sp_werror("invalid fcall size greater than msize", EIO);
		spc_disconnect_fsys(fs);
		return;
	}

	if (n < size)
		return;

	if (!sp_deserialize(fc, fc->pkt, fs->dotu)) {
		sp_werror("invalid fcall", EIO);
		spc_disconnect_fsys(fs);
		return;
	}

	if (spc_chatty) {
		fprintf(stderr, "-->>> (%p) ", fs);
		sp_printfcall(stderr, fc, fs->dotu);
		fprintf(stderr, "\n");
	}

	fs->ifcall = spc_fcall_alloc(fs->msize);
	if (!fs->ifcall) {
		spc_disconnect_fsys(fs);
		return;
	}

	if (n > size)
		memmove(fs->ifcall->pkt, fc->pkt + size, n - size);

	fs->ifcall->size = n - size;

	for(preq = NULL, req = fs->sent_reqs; req != NULL; preq = req, req = req->next)
		if (fc->tag == req->tag) 
			break;

	if (!req) {
		sp_werror("unexpected fcall", EIO);
		free(fc);
		return;
	}

	if (preq)
		preq->next = req->next;
	else
		fs->sent_reqs = req->next;

	if (fc->type!=Rerror && req->tc->type+1!=fc->type) {
		sp_werror(Emismatch, EIO);
		free(fc);
		fc = NULL;
	}

	(*req->cb)(req->cba, fc);
	if (fs->destroyed) {
		free(req);
		return;
	}

	if (!req->flushed) {
		spc_put_id(fs->tagpool, req->tag);
		free(req);
	}

	if (fs->ifcall->size) {
		fc = fs->ifcall;
		goto again;
	}
}

static void
spc_fd_write(Spcfsys *fs)
{
	int n;
	Spcreq *req;
	Spfcall *tc;

	if (!fs->pend_first)
		return;

	req = fs->pend_first;
	tc = req->tc;

	if (spc_chatty && fs->pend_pos == 0) {
		fprintf(stderr, "<<<-- (%p) ", fs);
		sp_printfcall(stderr, tc, fs->dotu);
		fprintf(stderr, "\n");
	}

	n = spfd_write(fs->spfd, tc->pkt + fs->pend_pos, tc->size - fs->pend_pos);
	if (n <= 0) {
		if (n == 0)
			spc_disconnect_fsys(fs);
		return;
	}

	fs->pend_pos += n;
	if (tc->size == fs->pend_pos) {
		fs->pend_pos = 0;
		fs->pend_first = req->next;
		if (req == fs->pend_last)
			fs->pend_last = NULL;

		req->next = fs->sent_reqs;
		fs->sent_reqs = req;
	}
}

static void
spc_notify(Spfd *spfd, void *aux)
{
	int ecode;
	char *ename;
	Spcfsys *fs;

	fs = aux;
	fs->in_notify++;
	sp_rerror(&ename, &ecode);
	if (ename)
		ename = strdup(ename);

	sp_werror(NULL, 0);
	if (spfd_can_read(spfd))
		spc_fd_read(fs);

	if (fs->destroyed) {
		free(fs);
		return;
	}

	if (!fs->spfd)
		goto error;

	if (spfd_can_write(spfd))
		spc_fd_write(fs);

	if (spfd_has_error(spfd))
		spc_disconnect_fsys(fs);

error:
	sp_rerror(&ename, &ecode);
	if (ecode) {
		if (spc_chatty)
			fprintf(stderr, "Error: %s: %d\n", ename, ecode);
		sp_werror(NULL, 0);
	}
	fs->in_notify--;
}

int
spc_rpcnb(Spcfsys *fs, Spfcall *tc, void (*cb)(void *, Spfcall *), void *cba)
{
	Spcreq *req;

	if (!fs->spfd) {
		sp_werror("disconnected", ECONNRESET);
		goto error;
	}

	if (fs->ename) {
		sp_werror(fs->ename, fs->ecode);
		goto error;
	}

	req = sp_malloc(sizeof(*req));
	if (!req)
		goto error;

	if (tc->type != Tversion) {
		tc->tag = spc_get_id(fs->tagpool);
		if (tc->tag == NOTAG) {
			free(req);
			sp_werror("tag pool full", EIO);
			goto error;
		}

		sp_set_tag(tc, tc->tag);
	}

	req->tag = tc->tag;
	req->tc = tc;
	req->rc = NULL;
	req->cb = cb;
	req->cba = cba;
	req->fs = fs;
	req->flushed = 0;
	req->next = NULL;

	if (fs->pend_last)
		fs->pend_last->next = req;
	else
		fs->pend_first = req;

	fs->pend_last = req;
	if (!fs->pend_first->next && spfd_can_write(fs->spfd)) 
		spc_fd_write(fs);

	return 0;

error:
	(*cb)(cba, NULL);
	return -1;
}

static void
spc_rpc_cb(void *cba, Spfcall *rc)
{
	int ecode;
	char *ename;
	Spcrpc *r;

	r = cba;
	r->rc = rc;
	sp_rerror(&ename, &ecode);
	if (ecode == 0) {
		ename = r->fs->ename;
		ecode = r->fs->ecode;
	}

	if (ecode) {
		r->ecode = ecode;
		r->ename = strdup(ename);
		if (!r->ename) {
			r->ename = Enomem;
			r->ecode = ENOMEM;
		}
	}
}

int
spc_rpc(Spcfsys *fs, Spfcall *tc, Spfcall **rc)
{
	char *ename;
	Spcrpc r;

	if (fs->fd < 0)
		return -1;

	if (rc)
		*rc = NULL;

	r.fs = fs;
	r.tc = tc;
	r.rc = NULL;
	r.ename = NULL;
	r.ecode = 0;
	
	spc_rpcnb(fs, tc, spc_rpc_cb, &r);
	while (!r.ename && !r.rc)
		sp_poll_once();

	if (r.ename) {
		sp_werror(r.ename, r.ecode);
		goto error;
	}

	if (r.rc && r.rc->type == Rerror) {
		ename = sp_strdup(&r.rc->ename);
		if (ename)
			sp_werror(ename, r.rc->ecode);

		free(ename);
		goto error;
	}

	free(r.ename);
	if (rc)
		*rc = r.rc;
	else
		free(r.rc);

	return 0;

error:
	if (r.ename != Enomem)
		free(r.ename);
	free(r.rc);
	return -1;
}

static Spfcall *
spc_fcall_alloc(u32 msize)
{
	Spfcall *fc;

	fc = sp_malloc(sizeof(*fc) + msize);
	if (!fc)
		return NULL;

	fc->pkt = (u8*) fc + sizeof(*fc);
	fc->size = msize;

	return fc;
}

int
spc_getladdr(Spcfsys *fs, char *buf, int buflen)
{
	if (fs->laddr) {
		strncpy(buf, fs->laddr, buflen);
		return 0;
	}

	return -1;
}

int
spc_getraddr(Spcfsys *fs, char *buf, int buflen)
{
	if (fs->raddr) {
		strncpy(buf, fs->raddr, buflen);
		return 0;
	}

	return -1;
}
