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
#include "spfs.h"
#include "spclient.h"
#include "spcimpl.h"

enum {
	Error,
	Remove,
	Reof,
};

static int spcfd_shutdown;
static Spcfd *spcfds;

static void spcfd_notify(Spfd *spfd, void *aux);
static void spcfd_read_cb(void *cba, Spfcall *rc);
static void spcfd_write_cb(void *cba, Spfcall *rc);
static void spcfd_send_read_request(Spcfd *spcfd);

Spcfd *
spcfd_add(Spcfid *fid, void (notify)(Spcfd *, void *), void *aux, u64 offset)
{
	int iounit;
	Spcfd *ret;

	iounit = fid->fsys->msize;
	if (fid->iounit && iounit > fid->iounit)
		iounit = fid->iounit;

	ret = sp_malloc(sizeof(*ret) + 2*iounit);
	if (!ret) 
		return NULL;

	ret->spfd = NULL;
	ret->fid = fid;
	ret->flags = 0;
	ret->iounit = iounit;
	ret->notify = notify;
	ret->aux = aux;
	ret->offset = offset;
	ret->rbuf = ((u8 *) ret) + sizeof(*ret);
	ret->rpos = 0;
	ret->wbuf = ret->rbuf + iounit;
	ret->wpos = 0;
	ret->rtc = NULL;
	ret->wtc = NULL;
	ret->next = spcfds;
	spcfds = ret;

	if (fid->mode==Oread || fid->mode==Ordwr)
		spcfd_send_read_request(ret);

	return ret;
}

Spcfd *
spcfd_add_fd(int fd, void (notify)(Spcfd *, void *), void *aux)
{
	Spcfd *ret;

	ret = sp_malloc(sizeof(*ret));
	if (!ret)
		return NULL;

	ret->spfd = spfd_add(fd, spcfd_notify, ret);
	ret->fid = NULL;
	ret->flags = 0;
	ret->iounit = 0;
	ret->notify = notify;
	ret->aux = aux;
	ret->offset = 0;
	ret->rbuf = NULL;
	ret->rpos = 0;
	ret->wbuf = NULL;
	ret->wpos = 0;
	ret->rtc = NULL;
	ret->wtc = NULL;
	ret->next = spcfds;
	spcfds = ret;

	return ret;
}

void 
spcfd_remove(Spcfd *spcfd)
{
	Spcfd *ps, *s;

	if (!spcfd->spfd && (spcfd->wpos>0 || spcfd->rtc)) {
		spcfd->flags |= Remove;
		return;
	}

	if (spcfd->spfd) {
		spfd_remove(spcfd->spfd);
		spcfd->spfd = NULL;
	}

	for(ps = NULL, s = spcfds; s != NULL; ps = s, s = s->next)
		if (s == spcfd) {
			if (ps)
				ps->next = s->next;
			else
				spcfds = s->next;

			free(s);
			break;
		}

/*
	if (spcfd_shutdown) {
		for(s = spcfds; s != NULL; s = s->next)
			if (s->wpos>0 || s->rtc)
				break;

		if (!s) {
			spcfd_shutdown = 0;
			sp_poll_stop();
		}
	}
*/
}

int
spcfd_can_write(Spcfd *spcfd)
{
	if (spcfd->spfd)
		return spfd_can_write(spcfd->spfd);

	return spcfd->wpos < spcfd->iounit;
}

int
spcfd_can_read(Spcfd *spcfd)
{
	if (spcfd->spfd)
		return spfd_can_read(spcfd->spfd);

	return spcfd->rpos>0 || spcfd->flags&Reof;
}

int
spcfd_has_error(Spcfd *spcfd)
{
	if (spcfd->spfd)
		return spfd_has_error(spcfd->spfd);

	return spcfd->flags & Error;
}

int
spcfd_done_writing(Spcfd *spcfd)
{
	return spcfd->wpos == 0;
}

void
spcfd_start_loop()
{
	Spcfd *s;

	for(s = spcfds; s != NULL; s = s->next)
		spcfd_send_read_request(s);

	sp_poll_loop();
}

void
spcfd_stop_loop()
{
	Spcfd *s;

	for(s = spcfds; s != NULL; s = s->next)
		if (s->wpos > 0)
			break;

	if (!s)
		sp_poll_stop();
	else 
		spcfd_shutdown = 1;
}

static void
spcfd_send_read_request(Spcfd *spcfd)
{
	if (!spcfd->rtc && !spcfd_shutdown && !(spcfd->flags&Reof)) {
		spcfd->rtc = sp_create_tread(spcfd->fid->fid, spcfd->offset, 
			spcfd->iounit - spcfd->rpos);
		if (spc_rpcnb(spcfd->fid->fsys, spcfd->rtc, spcfd_read_cb, spcfd) < 0) {
			spcfd->flags |= Error;
			free(spcfd->rtc);
			spcfd->rtc = NULL;
		}
	}
}

int 
spcfd_read(Spcfd *spcfd, void *buf, int buflen)
{
	int n;

	if (spcfd->spfd)
		return spfd_read(spcfd->spfd, buf, buflen);

	if (spcfd->flags & Reof)
		return 0;

	if (spcfd->rpos == 0) {
		sp_werror("read operation would block", EIO);
		return -1;
	}

	n = buflen;
	if (n > spcfd->rpos)
		n = spcfd->rpos;

	memmove(buf, spcfd->rbuf, n);
	if (n < spcfd->rpos)
		memmove(spcfd->rbuf, spcfd->rbuf + n, spcfd->rpos - n);
	spcfd->rpos -= n;

	spcfd_send_read_request(spcfd);
	return n;
}

int
spcfd_write(Spcfd *spcfd, void *buf, int buflen)
{
	int n;

	if (spcfd->spfd)
		return spfd_write(spcfd->spfd, buf, buflen);

	if (spcfd->wpos == spcfd->iounit) {
		sp_werror("write operation would block", EIO);
		return -1;
	}

	n = spcfd->iounit - spcfd->wpos;
	if (n > buflen)
		n = buflen;

	memmove(spcfd->wbuf + spcfd->wpos, buf, n);
	spcfd->wpos += n;

	if (!spcfd->wtc) {
		spcfd->wtc = sp_create_twrite(spcfd->fid->fid, spcfd->offset, 
			spcfd->wpos, spcfd->wbuf);
		if (spc_rpcnb(spcfd->fid->fsys, spcfd->wtc, spcfd_write_cb, spcfd) < 0) {
			free(spcfd->wtc);
			spcfd->wtc = NULL;
			return -1;
		}
	}

	return n;
}

static void
spcfd_notify(Spfd *spfd, void *aux)
{
	Spcfd *spcfd;

	spcfd = aux;
//	fprintf(stderr, "spcfd_notify %p %d %d %d\n", spcfd, spfd_can_read(spfd), spfd_can_write(spfd), spfd_has_error(spfd));
	(*spcfd->notify)(spcfd, spcfd->aux);
}

static void
spcfd_check_error(Spcfd *spcfd, Spfcall *rc)
{
	char *ename;

	if (rc && rc->type == Rerror) {
		ename = sp_strdup(&rc->ename);
		if (ename) {
			sp_werror(ename, rc->ecode);
			free(ename);
		}
	}
}

static void
spcfd_read_cb(void *cba, Spfcall *rc)
{
	int n, ecode;
	char *ename;
	Spcfd *spcfd;

	spcfd = cba;
	spcfd_check_error(spcfd, rc);
	sp_rerror(&ename, &ecode);
	if (ecode) {
		spcfd->flags |= Error;
		goto do_notify;
	}

	n = spcfd->rpos;
	if (rc->count) {
		memmove(spcfd->rbuf + spcfd->rpos, rc->data, rc->count);
		spcfd->rpos += rc->count;
		spcfd->offset += rc->count;
	} else
		spcfd->flags |= Reof;

do_notify:
	free(spcfd->rtc);
	spcfd->rtc = NULL;
	free(rc);

	if (spcfd->flags & Remove)
		spcfd_remove(spcfd);
	else
		(*spcfd->notify)(spcfd, spcfd->aux);

	sp_werror(NULL, 0);
}

static void
spcfd_write_cb(void *cba, Spfcall *rc)
{
	int ecode;
	char *ename;
	Spcfd *spcfd;

	spcfd = cba;

	spcfd_check_error(spcfd, rc);
	sp_rerror(&ename, &ecode);
	if (ecode) {
		spcfd->flags |= Error;
		goto do_notify;
	}

	spcfd->offset += rc->count;
	if (rc->count < spcfd->wpos)
		memmove(spcfd->wbuf, spcfd->wbuf + rc->count, spcfd->wpos - rc->count);

	spcfd->wpos -= rc->count;

do_notify:
	free(spcfd->wtc);
	spcfd->wtc = NULL;
	free(rc);
	if (spcfd->flags & Remove)
		spcfd_remove(spcfd);
	else
		(*spcfd->notify)(spcfd, spcfd->aux);

	sp_werror(NULL, 0);
}
