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

typedef struct Spcreq Spcreq;
typedef struct Spcpool Spcpool;

struct Spcpool {
	u32		maxid;
	int		msize;
	u8*		map;
};

struct Spcreq {
	u16		tag;
	Spfcall*	tc;
	Spfcall*	rc;
	void		(*cb)(void *, Spfcall *);
	void*		cba;

	Spcfsys*	fs;
	int		flushed;
	Spcreq*		next;
};

struct Spcfsys {
	int		fd;
	Spfd*		spfd;
	int		dotu;
	u32		msize;
	Spcfid*		root;
	Spcfid*		afid;

	char*		ename;
	int		ecode;

	Spcpool*	tagpool;
	Spcpool*	fidpool;
	Spfcall*	ifcall;

	int		pend_pos;
	Spcreq*		pend_first;
	Spcreq*		pend_last;
	Spcreq*		sent_reqs;

	int		destroyed;
	int		in_notify;
	char*		laddr;
	char*		raddr;
};

Spcfsys *spc_create_fsys(int fd, int msize);
void spc_disconnect_fsys(Spcfsys *fs);
void spc_destroy_fsys(Spcfsys *fs);
void spc_flush_requests(Spcfsys *fs, Spcfid *fid);

Spcpool *spc_create_pool(u32 maxid);
void spc_destroy_pool(Spcpool *p);
u32 spc_get_id(Spcpool *p);
void spc_put_id(Spcpool *p, u32 id);

Spcfid *spc_fid_alloc(Spcfsys *fs);
void spc_fid_free(Spcfid *fid);

int spc_rpc(Spcfsys *fs, Spfcall *tc, Spfcall **rc);
int spc_rpcnb(Spcfsys *fs, Spfcall *tc, void (*cb)(void *, Spfcall *), void *cba);
Spcfid *spc_walk(Spcfsys *fs, char *path);
int spc_wstatlen(Spstat *st);
void spc_stat2wstat(Spstat *st, Spwstat *wst, char **sbuf);
