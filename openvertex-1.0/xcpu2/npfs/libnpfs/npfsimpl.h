/*
 * Copyright (C) 2005 by Latchesar Ionkov <lucho@ionkov.net>
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

extern Npuserpool *np_unix_users;

/* fcall.c */
Npfcall *np_version(Npreq *req, Npfcall *tc);
Npfcall *np_auth(Npreq *req, Npfcall *tc);
Npfcall *np_attach(Npreq *req, Npfcall *tc);
Npfcall *np_flush(Npreq *req, Npfcall *tc);
Npfcall *np_walk(Npreq *req, Npfcall *tc);
Npfcall *np_open(Npreq *req, Npfcall *tc);
Npfcall *np_create(Npreq *req, Npfcall *tc);
Npfcall *np_read(Npreq *req, Npfcall *tc);
Npfcall *np_write(Npreq *req, Npfcall *tc);
Npfcall *np_clunk(Npreq *req, Npfcall *tc);
Npfcall *np_remove(Npreq *req, Npfcall *tc);
Npfcall *np_stat(Npreq *req, Npfcall *tc);
Npfcall *np_wstat(Npreq *req, Npfcall *tc);

/* fmt.c */
int np_printstat(FILE *f, Npstat *st, int dotu);
int np_dump(FILE *f, u8 *data, int datalen);

/* srv.c */
void np_srv_add_req(Npsrv *srv, Npreq *req);
void np_srv_remove_req(Npsrv *srv, Npreq *req);
void np_srv_add_workreq(Npsrv *srv, Npreq *req);
void np_srv_remove_workreq(Npsrv *srv, Npreq *req);
Npreq *np_req_alloc(Npconn *conn, Npfcall *tc);
Npreq *np_req_ref(Npreq*);
void np_req_unref(Npreq*);
void np_req_free(Npreq *req);
void np_srv_process_fcall(Npconn *conn, Npfcall *tc);
int sreuid(int a, int b);
int sregid(int a, int b);
