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
#include <assert.h>
#include "spfs.h"
#include "spfsimpl.h"

static Spfcall *sp_conn_new_incall(Spconn *conn);
static void sp_conn_free_incall(Spconn *, Spfcall *);
static void sp_conn_notify(Spfd *spfd, void *aux);
static int sp_conn_read(Spconn *conn);
static void sp_conn_write(Spconn *conn);

Spconn*
sp_conn_create(Spsrv *srv, char *address, int fdin, int fdout)
{
	Spconn *conn;

	conn = malloc(sizeof(*conn));
	if (!conn)
		return NULL;

	conn->address = address;
	conn->srv = srv;
	conn->msize = srv->msize;
	conn->dotu = srv->dotu;
	conn->fidpool = NULL;
	conn->freercnum = 0;
	conn->freerclist = NULL;
	conn->ifcall = NULL;
	conn->ofcall_pos = 0;
	conn->ofcall_first = NULL;
	conn->ofcall_last = NULL;
	conn->fdin = fdin;
	conn->fdout = fdout;

	conn->spfdin = spfd_add(fdin, sp_conn_notify, conn);
	if (!conn->spfdin) {
		free(conn);
		return NULL;
	}

	if (fdin == fdout)
		conn->spfdout = conn->spfdin;
	else {
		conn->spfdout = spfd_add(fdout, sp_conn_notify, conn);
		if (!conn->spfdout) {
			spfd_remove(conn->spfdin);
			free(conn);
			return NULL;
		}
	}

	sp_srv_add_conn(srv, conn);
	return conn;
}

static void
sp_conn_destroy(Spconn *conn)
{
	close(conn->fdin);
	if (conn->fdout != conn->fdin)
		close(conn->fdin);

	spfd_remove(conn->spfdin);
	if (conn->spfdout != conn->spfdin)
		spfd_remove(conn->spfdout);

	sp_srv_remove_conn(conn->srv, conn);
	sp_conn_reset(conn, 0, 0);
	free(conn->address);
	free(conn);
}

void
sp_conn_reset(Spconn *conn, u32 msize, int dotu)
{
	Spsrv *srv;
	Spreq *req, *req1;
	Spfcall *fc, *fc1, *rc;

	srv = conn->srv;

	/* first flush all outstanding requests */
	req = srv->reqs_first;
	while (req != NULL) {
		req1 = req->next;
		if (req->conn == conn) {
			sp_srv_remove_req(srv, req);
			sp_conn_respond(conn, req->tcall, NULL);
			sp_req_free(req);
		}
		req = req1;
	}

	/* flush all working requests */
	/* if there are pending requests, the server should define flush, 
	   otherwise we loop forever */
again:
	req = conn->srv->workreqs;
	while (req != NULL) {
		if (req->conn == conn && (msize==0 || req->tcall->type != Tversion)) {
			if (srv->flush)
				rc = (*srv->flush)(req);
			else
				rc = NULL;

			goto again;
		}

		req = req->next;
	}

	/* clean the incoming fcall */
	sp_conn_free_incall(conn, conn->ifcall);
	conn->ifcall = NULL;

	/* clean the outgoing fcalls */
	fc = conn->ofcall_first;
	while (fc != NULL) {
		fc1 = fc->next;
		free(fc);
		fc = fc1;
	}

	conn->ofcall_first = NULL;
	conn->ofcall_last = NULL;
	conn->ofcall_pos = 0;

	/* free old pool of fcalls */	
	fc = conn->freerclist;
	conn->freerclist = NULL;
	while (fc != NULL) {
		fc1 = fc->next;
		free(fc);
		fc = fc1;
	}

	if (conn->fidpool) {
		sp_fidpool_destroy(conn->fidpool);
		conn->fidpool = NULL;
	}

	if (msize) {
		conn->msize = msize;
		conn->dotu = dotu;
		conn->fidpool = sp_fidpool_create();
	}
}

static void
sp_conn_notify(Spfd *spfd, void *aux)
{
	int n;
	Spconn *conn;

	conn = aux;
	n = 0;
	if (spfd_can_read(spfd))
		n = sp_conn_read(conn);

	if (!n && spfd_can_write(spfd))
		sp_conn_write(conn);

	if (n || spfd_has_error(spfd)) {
		sp_werror(NULL, 0);
		sp_conn_destroy(conn);
	}
}

static int
sp_conn_read(Spconn *conn)
{
	int n, size;
	Spsrv *srv;
	Spfcall *fc, *fc1;

	srv = conn->srv;

	/* if we are sending Enomem error back, block all reading */
	if (srv->enomem)
		return 0;

	if (!conn->ifcall) {
		conn->ifcall = sp_conn_new_incall(conn);
		conn->ifcall->size = 0;
	}

	fc = conn->ifcall;
	n = spfd_read(conn->spfdin, fc->pkt + fc->size, conn->msize - fc->size);
	if (n == 0)
		return -1;
	else if (n < 0)
		return 0;

	fc->size += n;

again:
	n = fc->size;
	if (n < 4)
		return 0;

	size = fc->pkt[0] | (fc->pkt[1]<<8) | (fc->pkt[2]<<16) | (fc->pkt[3]<<24);
	if (n < size)
		return 0;

	if (size > conn->msize) {
		fprintf(stderr, "error: packet too big\n");
		close(conn->fdin);
		if (conn->fdout != conn->fdin)
			close(conn->fdout);
		return 0;
	}

	if (!sp_deserialize(fc, fc->pkt, conn->dotu)) {
		fprintf(stderr, "error while deserializing\n");
		close(conn->fdin);
		if (conn->fdout != conn->fdin)
			close(conn->fdout);
		return 0;
	}

	if (srv->debuglevel) {
		fprintf(stderr, "<<< (%p) ", conn);
		sp_printfcall(stderr, fc, conn->dotu);
		fprintf(stderr, "\n");
	}

	fc1 = sp_conn_new_incall(conn);
	if (n > size)
		memmove(fc1->pkt, fc->pkt + size, n - size);

	fc1->size = n - size;

	conn->ifcall = fc1;
	sp_srv_process_fcall(conn, fc);

	fc = conn->ifcall;
	if (fc && fc->size > 0)
		goto again;

	return 0;
}

static void
sp_conn_write(Spconn *conn)
{
	int n;
	Spfcall *rc;
	Spsrv *srv;

	srv = conn->srv;
	rc = conn->ofcall_first;
	if (!rc)
		return;

	if (conn->srv->debuglevel && conn->ofcall_pos==0) {
		fprintf(stderr, ">>> (%p) ", conn);
		sp_printfcall(stderr, rc, conn->dotu);
		fprintf(stderr, "\n");
	}

	n = spfd_write(conn->spfdout, rc->pkt + conn->ofcall_pos, rc->size - conn->ofcall_pos);
	if (n <= 0)
		return;

	conn->ofcall_pos += n;
	if (conn->ofcall_pos == rc->size) {
		conn->ofcall_first = rc->next;
		if (conn->ofcall_last == rc)
			conn->ofcall_last = NULL;

		conn->ofcall_pos = 0;
		if (rc==srv->rcenomem || rc==srv->rcenomemu) {
			/* unblock reading and read some messages if we can */
			srv->enomem = 0;
			if (spfd_can_read(conn->spfdin))
				sp_conn_read(conn);
		} else
			free(rc);
	}
}

void
sp_conn_respond(Spconn *conn, Spfcall *tc, Spfcall *rc)
{
	if (!rc) {
		sp_conn_free_incall(conn, tc);
		return;
	}

	sp_set_tag(rc, tc->tag);
	sp_conn_free_incall(conn, tc);

	if (conn->ofcall_last)
		conn->ofcall_last->next = rc;

	if (!conn->ofcall_first)
		conn->ofcall_first = rc;

	conn->ofcall_last = rc;
	rc->next = NULL;

	if (!conn->ofcall_first->next && spfd_can_write(conn->spfdout))
		sp_conn_write(conn);
}

static Spfcall *
sp_conn_new_incall(Spconn *conn)
{
	Spfcall *fc;

	if (conn->freerclist) {
		fc = conn->freerclist;
		conn->freerclist = fc->next;
		conn->freercnum--;
	} else {
		fc = malloc(sizeof(*fc) + conn->msize);
	}

	if (!fc)
		return NULL;

	fc->pkt = (u8*) fc + sizeof(*fc);
	return fc;
}

static void
sp_conn_free_incall(Spconn* conn, Spfcall *rc)
{
	Spfcall *r;

	if (!rc)
		return;

	for(r = conn->freerclist; r != NULL; r = r->next)
		if (rc == r)
			abort();

	if (conn->freercnum < 64) {
		rc->next = conn->freerclist;
		conn->freerclist = rc;
		rc = NULL;
	}

	if (rc)
		free(rc);
}
