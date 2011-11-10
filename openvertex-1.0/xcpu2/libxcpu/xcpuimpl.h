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

typedef struct Xpfile Xpfile;
typedef struct Xpcopy Xpcopy;

struct Xpfile {
	Spcfsys*	fs;
	char*		name;
	u32		perm;
	int		create;	/* if 1, create, otherwise open witn Otrunc */

	char*		path;	/* if not NULL the file's content is read from the fs */
	char*		buf;	/* if path NULL, the content of the file, freed when Rxfile is destroyed */
	int		bufsize;
	int		buflen;
	Xpfile*		next;

	/* required for the copying */
	int		fd;
	Spcfid*		fid;
	Spcfd*		spcfd;
	int		pos;
};

struct Xpcopy {
        Xpfile*         files;
        Xpfile*         cfile;
	void		(*finish)(Xpcopy *, void *);
	void*		finishaux;
};

struct Xpsession {
	Xpnode*		node;
	char*		sid;
	char*		jid;	/* job id */
	Xpcommand*	command;

	/* implementation specific */
	Spcfsys*	fs;
	char*		ename;
	int		ecode;
	char*		exitcode;
	Spuser*		user;
	Xkey*		ukey;
	Spcfid*		pkfid;

	/* session fids */
	Spcfid*		ctl;
	Spcfid*		wait;
	Spcfid*		in;
	Spcfid*		out;
	Spcfid*		err;

	/* spcfds */
	Spcfd*		wspcfd;
	Spcfd*		ispcfd;
	Spcfd*		ospcfd;
	Spcfd*		espcfd;

	char*		inbuf;
	int		insize;
	int		inpos;
	int		closein;

	char		outbuf[512];
	int		outpos;

	char		errbuf[512];
	int		errpos;

	Xpfile*		files;
	Xpcopy*		copyf;
};

typedef struct Xcmd Xcmd;
struct Xcmd {
	Spstr *cmd;
	Spuser *adminuser;
	Xkey *adminkey;
};

extern int xp_ldd_support;

int xp_file_create_from_file(Xpfile **xpf, Spcfsys *fs, char *name, char *path);
int xp_file_create_from_buf(Xpfile **xpf, Spcfsys *fs, char *name, char *buf, int buflen);
void xp_file_destroy(Xpfile *f);
void xp_file_destroy_all(Xpfile *f);
Xpcopy *xp_file_copy_start(Xpfile *files);
int xp_file_copy_finish(Xpcopy *c);

Xpsessionset *xp_sessionset_alloc(int n);
Xpsessionset *xp_sessionset_by_jobid(Xpnodeset *nds, char *jobid, Xpcommand *cm);
int xp_sessionset_split_by_arch(Xpsessionset *ss, Xpsessionset ***ssa);
Xpsession *xp_session_create(Xpnode *, Spuser *, Xkey *);
void xp_session_destroy(Xpsession *);
Xpsession* xp_session_attach(Xpnode *nd, char *sid, Spuser *user, Xkey *key);
int xp_session_setup_start(Xpsession *ss, char *env, char *ns, char *argv,
	char *ctl);
int xp_session_setup_finish(Xpsession *ss);
int xp_session_close_stdin(Xpsession *ss);
int xp_session_get_passkey(Xpsession *ss, char *pk, int pklen);

Xpsessionset *xp_sessionset_create(Xpnodeset *nodes, Xpcommand *);
void xp_sessionset_destroy(Xpsessionset *);

int xp_ldd(char *binary, char *sysroot, char ***deps);
Spsrv *ufs_create_srv(int *port);

int xp_ctl_cmd(Xpnode *nd, void *xcmd);
Xcmd *xcmd_init(Spstr *cmd, char *adminkey);
void xcmd_destroy(Xcmd *xcmd);
