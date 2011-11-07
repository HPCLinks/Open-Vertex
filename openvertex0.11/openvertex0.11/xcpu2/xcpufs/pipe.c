#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include "spfs.h"
#include "spclient.h"
#include "libxauth.h"
#include "xcpufs.h"

static void pip_notify(Spfd *spfd, void *aux);
static void pip_disconnect(Xfilepipe *p);

Xfilepipe *
pip_create(int direction)
{
	int pip[2];
	Xfilepipe *p;

	p = sp_malloc(sizeof(*p));
	if (!p)
		return NULL;

	p->err = 0;
	p->direction = direction;
	p->bufsize = 1024;
	p->buf = sp_malloc(p->bufsize);
	if (!p->buf) {
		free(p);
		return NULL;
	}

	p->buflen = 0;
	if (pipe(pip) < 0) {
		sp_uerror(errno);
		free(p->buf);
		free(p);
		return NULL;
	}
	
	if (direction == Read) {
		p->lfd = pip[0];
		p->rfd = pip[1];
	} else {
		p->lfd = pip[1];
		p->rfd = pip[0];
	}

	fcntl(p->lfd, F_SETFD, FD_CLOEXEC);
	p->reqs = NULL;
	p->lspfd = spfd_add(p->lfd, pip_notify, p);
//	fprintf(stderr, "pip_create %p lfd %d rfd %d\n", p, p->lfd, p->rfd);

	return p;
}

void
pip_destroy(Xfilepipe *p)
{
//	fprintf(stderr, "pip_destroy pip %p\n", p);
	if (p->lspfd) {
		spfd_remove(p->lspfd);
		p->lspfd = NULL;
	}
	if (p->lfd >= 0)
		close(p->lfd);
	if (p->rfd >= 0)
		close(p->rfd);
	p->err = EPIPE;
	free(p->buf);
	free(p);
}

static void
pip_read_buf(Xfilepipe *p)
{
	int n, m, len, fid;
	Xpipereq *preq, *ppreq, *preq1;
	Spreq *req;
	Spfcall *rc;

	if (!p->reqs)
		return;

	len = p->buflen;
	ppreq = NULL;
	preq = p->reqs;
	while (preq != NULL) {
		n = 0;
		fid = preq->fid->fid;
		while (preq && preq->fid->fid==fid) {
			if (n<=p->buflen || !p->lspfd) {
				req = preq->req;
				if (n < p->buflen)
					m = p->buflen - n;
				else
					m = 0;

				if (m > req->tcall->count)
					m = req->tcall->count;

				rc = sp_create_rread(m, (u8 *) p->buf + n);
				sp_respond(req, rc);
				n += m;
				if (!ppreq)
					p->reqs = preq->next;
				else
					ppreq->next = preq->next;

				preq1 = preq->next;
				free(preq);
				preq = preq1;
			} else {
				ppreq = preq;
				preq = preq->next;
			}
		}

		if (len > n)
			len = n;
	}

	if (len != p->buflen)
		memmove(p->buf, p->buf + len, p->buflen - len);

	p->buflen -= len;
}

static void
pip_read_eof(Xfilepipe *p)
{
	int n;
	char *buf;

	/* if the pipe was closed, we are not going to be called anymore
	   so we need to read all the data now */
	while (1) {
		n = 32;
		if (p->buflen+n > p->bufsize) {
			buf = realloc(p->buf, p->bufsize + n);
			if (!buf) 
				return;

			p->buf = buf;
			p->bufsize += n;
		}

		n = spfd_read(p->lspfd, p->buf + p->buflen, p->bufsize - p->buflen);
		if (n <= 0)
			break;

		p->buflen += n;
	}
}

static void
pip_read(Xfilepipe *p)
{
	int n;

//	fprintf(stderr, "pip_read %p %d %d %d\n", p, spfd_can_read(p->lspfd), spfd_can_write(p->lspfd), spfd_has_error(p->lspfd));
	if (spfd_has_error(p->lspfd)) {
		pip_read_eof(p);
		pip_read_buf(p);
		return;
	}

	if (p->direction != Read)
		return;

	if (p->buflen < p->bufsize) {
		n = spfd_read(p->lspfd, p->buf + p->buflen, p->bufsize - p->buflen);
		if (n > 0) {
//			fprintf(stderr, "pip_read %p read %d bytes\n", p, n);
			p->buflen += n;
		}
	}

	pip_read_buf(p);
}

static void
pip_write(Xfilepipe *p)
{
	int n;
	Xpipereq *preq;
	Spfcall *tc, *rc;

	if (!p->reqs || p->direction!=Write)
		return;

	preq = p->reqs;
	tc = preq->req->tcall;

	n = spfd_write(p->lspfd, tc->data + p->buflen, tc->count - p->buflen);
	if (n <= 0)
		return;

	p->buflen += n;
	if (p->buflen == tc->count) {
		rc = sp_create_rwrite(p->buflen);
		sp_respond(preq->req, rc);
		p->reqs = preq->next;
		free(preq);
		p->buflen = 0;
	}
}

static void
pip_disconnect(Xfilepipe *p)
{
	Spfcall *rc;
	Xpipereq *preq, *preq1;

	if (p->lspfd)
		spfd_remove(p->lspfd);
	p->lspfd = NULL;
	p->err = EPIPE;

	if (p->direction == Read) {
//		if (p->buflen > 0)
			pip_read_buf(p);

//		preq = p->reqs;
//		while (preq != NULL) {
//			preq1 = preq->next;
//			rc = sp_create_rread(0, NULL);
//			sp_respond(preq->req, rc);
//			free(preq);
//			preq = preq1;
//		}
//		p->reqs = NULL;
	} else if (p->direction == Write) {
		preq = p->reqs;
		while (preq != NULL) {
			preq1 = preq->next;
			rc = sp_create_rwrite(p->buflen);
			sp_respond(preq->req, rc);
			p->buflen = 0;
			free(preq);
			preq = preq1;
		}
		p->reqs = NULL;
	}
}

static void
pip_notify(Spfd *spfd, void *aux)
{
	Xfilepipe *p;

	p = aux;
//	fprintf(stderr, "pip_notify %p %d %d %d\n", spfd, spfd_can_read(spfd), spfd_can_write(spfd), spfd_has_error(spfd));
	if (p->buflen>0 || (p->direction==Read && spfd_can_read(spfd)))
		pip_read(p);

	if (spfd_can_write(spfd))
		pip_write(p);

	if (spfd_has_error(spfd)) {
		pip_read_eof(p);
		pip_disconnect(p);
	}
}

int
pip_addreq(Xfilepipe* p, Spreq *req)
{
	Spfcall *rc;
	Xpipereq *r, *preq, *ppreq;

//	fprintf(stderr, "pip_addreq pip %p fid %d req %p\n", p, req->tcall->fid, req);
//	if (p->err)
//		return 0;

	r = sp_malloc(sizeof(*preq));
	if (!r) 
		return 0;

	r->pip = p;
	r->req = req;
	r->fid = req->fid;
	r->next = NULL;

	for(ppreq = NULL, preq = p->reqs; preq != NULL; ppreq = preq, preq = preq->next)
		if (preq->fid->fid > r->fid->fid)
			break;

	if (!ppreq)
		p->reqs = r;
	else
		ppreq->next = r;

	r->next = preq;
	if (p->lspfd)
		pip_notify(p->lspfd, p);
	else if (p->direction == Read) {
		if (!p->buflen) {
			rc = sp_create_rread(0, NULL);
			sp_respond(req, rc);
		} else
			pip_read_buf(p);
	} else {
		sp_uerror(EPIPE);
		return 0;
	}

	return 1;
}

int
pip_flushreq(Xfilepipe *p, Spreq *req)
{
	Xpipereq *preq, *ppreq;

	for(ppreq = NULL, preq = p->reqs; preq != NULL; ppreq = preq, preq = preq->next)
		if (preq->req == req) {
			if (ppreq)
				ppreq->next = preq->next;
			else
				p->reqs = preq->next;

			free(preq);
			return 1;
		}

	return 0;
}

void
pip_close_remote(Xfilepipe *p)
{
	if (p->rfd >= 0)
		close(p->rfd);
	p->rfd = -1;
}

void
pip_close_local(Xfilepipe *p)
{
	if (p->lfd >= 0)
		close(p->lfd);
	p->lfd = -1;
}
