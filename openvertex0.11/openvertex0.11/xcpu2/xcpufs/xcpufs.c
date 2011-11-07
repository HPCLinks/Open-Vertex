#include <stdlib.h>
#include <stdio.h>
/* what a kludge! see man 2 pread */
//#define _XOPEN_SOURCE 500
/* the man page is wrong, here's what the headers say: */
#define __USE_UNIX98	1
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/mount.h>
#include <sched.h>
#include <ctype.h>
#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "xcpu.h"
#include "libxauth.h"
#include "xcpufs.h"

static Spfile *dir_first(Spfile *);
static Spfile *dir_next(Spfile *, Spfile *);
static void session_destroy(Spfile *);
static void session_remove_dir(Xsession *xs);
static int clone_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static int clone_openfid(Spfilefid *);
static int env_openfid(Spfilefid *);
static void clone_closefid(Spfilefid *);
static int clone_wstat(Spfile *, Spstat *);
static int procs_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static int procs_write(Spfilefid *, u64, u32, u8 *, Spreq *);
static int procs_openfid(Spfilefid *);
static void procs_closefid(Spfilefid *);
static int ctl_write(Spfilefid *f, u64 offset, u32 count, u8 *data, Spreq *req);
static int ctl_wstat(Spfile *, Spstat *);
static int session_wstat(Spfile *, Spstat *);
static int sctl_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static int sctl_write(Spfilefid *f, u64 offset, u32 count, u8 *data, Spreq *req);
static int sctl_wstat(Spfile *, Spstat *);
static int filebuf_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static int filebuf_write(Spfilefid *, u64, u32, u8 *, Spreq *);
static int filebuf_wstat(Spfile *, Spstat *);
static int filepipe_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static int filepipe_write(Spfilefid *, u64, u32, u8 *, Spreq *);
static int stdio_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static int stdio_write(Spfilefid *, u64, u32, u8 *, Spreq *);
static int wait_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static int id_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static int pkey_openfid(Spfilefid *);
static void pkey_closefid(Spfilefid *);
static int pkey_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static int pwent_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static int grent_read(Spfilefid *, u64, u32, u8 *, Spreq *);
static void reftrack_ref(Spfile *, Spfilefid *);
static void reftrack_unref(Spfile *, Spfilefid *);
static int signame2signo(char *sig);
static Spfile *create_file(Spfile *parent, char *name, u32 mode, u64 qpath, 
	void *ops, Spuser *usr, void *aux);
static int ignore_wstat(Spfile *, Spstat *);

static int xclone(Spfid *fid, Spfid *newfid);
static int xwalk(Spfid *fid, Spstr *wname, Spqid *wqid);
static Spfcall *xopen(Spfid *fid, u8 mode);
static Spfcall *xcreate(Spfid *fid, Spstr *name, u32 perm, u8 mode, Spstr *extension);
static Spfcall* xread(Spfid *fid, u64 offset, u32 count, Spreq *);
static Spfcall* xwrite(Spfid *fid, u64 offset, u32 count, u8 *data, Spreq *);
static Spfcall* xclunk(Spfid *fid);
static Spfcall* xremove(Spfid *fid);
static Spfcall* xstat(Spfid *fid);
static Spfcall* xwstat(Spfid *fid, Spstat *stat);
static void xfiddestroy(Spfid *fid);

static void sigchld_notify(Spfd *spfd, void *aux);
static void sigchld_handler(int sig);
static int xexec(Xsession *xs, char *exec);
static int session_set_id(Xsession *xs, char *id);

Spauth xauth = {
	.startauth = xauth_startauth,
	.checkauth = xauth_checkauth,
	.read = xauth_read,
	.write = xauth_write,
	.clunk = xauth_clunk,
};

Spdirops root_ops = {
	.first = dir_first,
	.next = dir_next,
};

Spdirops session_ops = {
	.first = dir_first,
	.next = dir_next,
	.wstat = session_wstat,
	.destroy = session_destroy,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops clone_ops = {
	.read = clone_read,
	.openfid = clone_openfid,
	.closefid = clone_closefid,
	.wstat = clone_wstat,
};

Spfileops procs_ops = {
	.read = procs_read,
	.write = procs_write,
	.openfid = procs_openfid,
	.closefid = procs_closefid,
};

Spfileops state_ops = {
	.read = filebuf_read,
	.write = filebuf_write,
	.wstat = filebuf_wstat,
};

Spfileops ctl_ops = {
	.write = ctl_write,
	.wstat = ctl_wstat,
};

Spfileops sctl_ops = {
	.read = sctl_read,
	.write = sctl_write,
	.wstat = sctl_wstat,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops argv_ops = {
	.read = filebuf_read,
	.write = filebuf_write,
	.wstat = filebuf_wstat,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops env_ops = {
	.openfid = env_openfid,
	.read = filebuf_read,
	.write = filebuf_write,
	.wstat = filebuf_wstat,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops stdin_ops = {
	.read = filepipe_read,
	.write = filepipe_write,
	.wstat = ignore_wstat,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops stdout_ops = {
	.read = filepipe_read,
	.write = filepipe_write,
	.wstat = ignore_wstat,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops stderr_ops = {
	.read = filepipe_read,
	.write = filepipe_write,
	.wstat = ignore_wstat,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops stdio_ops = {
	.read = stdio_read,
	.write = stdio_write,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops wait_ops = {
	.read = wait_read,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops id_ops = {
	.read = id_read,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops fbuf_ops = {
	.read = filebuf_read,
	.write = filebuf_write,
	.wstat = filebuf_wstat,
};

Spfileops fpipe_ops = {
	.read = filepipe_read,
	.write = filepipe_write,
	.wstat = ignore_wstat,
};

Spfileops pkey_ops = {
	.openfid = pkey_openfid,
	.closefid = pkey_closefid,
	.read = pkey_read,
};

Spfileops globns_ops = {
	.read = filebuf_read,
	.write = filebuf_write,
	.wstat = filebuf_wstat,
};

Spfileops ns_ops = {
	.read = filebuf_read,
	.write = filebuf_write,
	.wstat = filebuf_wstat,
	.ref = reftrack_ref,
	.unref = reftrack_unref,
};

Spfileops pwent_ops = {
	.read = pwent_read,
};

Spfileops grent_ops = {
	.read = grent_read,
};


extern char **environ;
extern int spc_chatty;

static int session_next_id;
static Spfile *root;
static Spuser *user;
static Xfilebuf archbuf;
static Xfilebuf envbuf;
static Xfilebuf statebuf;
static Xfilebuf nsbuf;
static char *tmppath = "/tmp";
static int chld_fd;
char *ctlbuf;

static int debuglevel;
Xsession *sessions;
int sameuser;
int retaintmpdir = 0;
Spsrv *srv;
Spuser *adminuser;
Spgroup *admingroup;
Xkey *adminkey;

void
change_user(Spuser *user)
{
	if (!sameuser)
		sp_change_user(user);
}

static void
bufinit(Xfilebuf *fbuf)
{
	fbuf->size = 0;
	fbuf->buf = NULL;
}

static int
bufread(Xfilebuf *fbuf, u64 offset, u32 count, u8 *data)
{
	if (offset+count > fbuf->size)
		count = fbuf->size - offset;
 
	if (count < 0)
		count = 0;

	memmove(data, fbuf->buf + offset, count);
	return count;
}

static int
bufwrite(Xfilebuf *fbuf, u64 offset, u32 count, void *data)
{
	char *tbuf;

	if (offset+count > fbuf->size) {
		tbuf = realloc(fbuf->buf, offset + count);
		if (tbuf) {
			fbuf->buf = tbuf;
			fbuf->size = offset + count;
		}
	}

	if (offset + count > fbuf->size)
		count = fbuf->size - offset;

	if (count < 0)
		count = 0;

	memmove(fbuf->buf + offset, data, count);

	return count;
}

static void
bufsetsize(Xfilebuf *fbuf, int size)
{
	if (fbuf->size < size)
		bufwrite(fbuf, size, 0, NULL);
	else
		fbuf->size = size;
}

static void
buffree(Xfilebuf *fbuf)
{
	fbuf->size = 0;
	free(fbuf->buf);
}

static int
xrmdir(char *dir)
{
	int n, dlen, namlen;
	DIR *d;
	struct dirent *de;
	char *buf;

	dlen = strlen(dir);
	d = opendir(dir);
	if (!d)
		return errno;

	n = 0;
	while (!n && (de = readdir(d)) != NULL) {\
		namlen = strlen(de->d_name);
		if (namlen==1 && *de->d_name=='.')
			continue;

		if (namlen==2 && !memcmp(de->d_name, "..", 2))
			continue;

		buf = malloc(dlen + namlen + 2);
		sprintf(buf, "%s/%s", dir, de->d_name);
		if (de->d_type == DT_DIR)
			n = xrmdir(buf);
		else 
			if (unlink(buf) < 0)
				n = errno;
		free(buf);
	}
	closedir(d);

	if (!n && rmdir(dir)<0)
		n = errno;

	return n;
}

static int 
filebuf_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	Xfilebuf *fbuf;

	fbuf = fid->file->aux;
	return bufread(fbuf, offset, count, data);
}

static int
filebuf_write(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	int ret;
	Xfilebuf *fbuf;

	fbuf = fid->file->aux;
	ret = bufwrite(fbuf, offset, count, data);
	fid->file->length = fbuf->size;

	return ret;
}

static int
ignore_wstat(Spfile *f, Spstat *stat)
{
	return 1;
}

static int
filebuf_wstat(Spfile *f, Spstat *stat)
{
	Xfilebuf *fbuf;

	fbuf = f->aux;
	if (f->length != stat->length)
		bufsetsize(fbuf, stat->length);

	return 1;
}

static int
filepipe_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	Xfilepipe *p;

	p = fid->file->aux;
	if (!p) {
		sp_werror("redirected to local file", EIO);
		return 0;
	}

	if (p->direction != Read) {
		sp_werror("Cannot read", EPERM);
		return 0;
	}

	return pip_addreq(p, req)?-1:0;
}

static int
filepipe_write(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	Xfilepipe *p;

	p = fid->file->aux;
	if (!p) {
		sp_werror("redirected to local file", EIO);
		return 0;
	}

	if (p->direction != Write) {
		sp_werror("Cannot write", EPERM);
		return 0;
	}

	return pip_addreq(p, req)?-1:0;
}

Xsession*
session_create(int msize)
{
	int n;
	char *buf;
	Xsession *s, *ps, *xs;

	buf = NULL;
	xs = sp_malloc(sizeof(*xs));
	if (!xs)
		return NULL;

	xs->refcount = 1;
	xs->state = Initializing;
	xs->mode = Normal;
	xs->gid = strdup("");
	xs->lid = 0;
	bufinit(&xs->argv);
	bufinit(&xs->env);
	bufwrite(&xs->env, 0, envbuf.size, envbuf.buf);
	bufinit(&xs->ns);
	bufwrite(&xs->ns, 0, nsbuf.size, nsbuf.buf);
	xs->ctl = NULL;
	xs->ctlreq = NULL;
	xs->ctlpos = 0;
	xs->stin = NULL;
	xs->stout = NULL;
	xs->sterr = NULL;
	xs->stinfname = NULL;
	xs->stoutfname = NULL;
	xs->sterrfname = NULL;
	xs->execpath = NULL;
	xs->pid = -1;
	xs->exitstatus = NULL;
	xs->sroot = NULL;
	xs->fsdir = NULL;
	xs->waitreqs = NULL;
	xs->next = NULL;
	xs->upfs = NULL;
	xs->uprefix = NULL;

	n = strlen(tmppath) + 16;
	buf = sp_malloc(n);
	if (!buf) 
		goto error;

	sprintf(buf, "%s/xcpu-XXXXXX", tmppath);
	xs->dirpath = mkdtemp(buf);
	if (!xs->dirpath) {
		sp_uerror(errno);
		goto error;
	}
	chmod(xs->dirpath, 0770);

	xs->stin = pip_create(Write);
	if (!xs->stin)
		goto error;
	xs->stout = pip_create(Read);
	if (!xs->stout)
		goto error;
	xs->sterr = pip_create(Read);
	if (!xs->sterr)
		goto error;

	xs->sid = session_next_id;
	session_next_id++;
	for(ps=NULL, s=sessions; s!=NULL; ps=s, s=s->next)
		if (s->sid >= xs->sid)
			break;

	if (s && s->sid == xs->sid) {
		xs->sid++;
		while (s!=NULL && xs->sid==s->sid) {
			xs->sid++;
			if (xs->sid == INT_MAX) {
				xs->sid = 0;
				s = sessions;
				ps = NULL;
			} else {
				ps = s;
				s = s->next;
			}
		}
	}

	if (ps) {
		xs->next = ps->next;
		ps->next = xs;
	} else {
		xs->next = sessions;
		sessions = xs;
	}

	return xs;

error:
	if (xs->stin)
		pip_destroy(xs->stin);
	if (xs->stout)
		pip_destroy(xs->stout);
	if (xs->sterr)
		pip_destroy(xs->sterr);

	free(xs->gid);
	free(buf);
	free(xs);
	return NULL;
}

static void
session_destroy(Spfile *file)
{
	Xsession *xs, *s, *ps;

	xs = file->aux;
	for(s=sessions, ps=NULL; s != NULL; ps=s, s=s->next)
		if (s == xs)
			break;

	if (ps)
		ps->next = xs->next;
	else
		sessions = xs->next;

	free(xs->gid);
	buffree(&xs->argv);
	buffree(&xs->env);
	free(xs->ctl);
	pip_destroy(xs->stin);
	pip_destroy(xs->stout);
	pip_destroy(xs->sterr);

	if (xs->execpath && (! retaintmpdir)) {
		unlink(xs->execpath);
		free(xs->execpath);
	}

	if (xs->dirpath && (! retaintmpdir)) {
		xrmdir(xs->dirpath);
		free(xs->dirpath);
	}

	if (xs->pid != -1)
		kill(xs->pid, SIGTERM);

	if (xs->upfs) {
		spc_umount(xs->upfs);
		xs->upfs = NULL;
	}
	free(xs->uprefix);
	free(xs->exitstatus);
	free(xs);
}

static int
session_add_dir(Xsession *xs, Spuser *user)
{
	u64 qpath;
	char buf[32];
	Spfile *sroot;

	snprintf(buf, sizeof buf, "%d", xs->sid);
	qpath = QPATH(xs->sid);
	sroot = create_file(root, buf, 0555 | Dmdir, qpath, &session_ops,
		user, xs);
	if (!sroot)
		return 0;

	xs->sroot = sroot;
	if (!create_file(sroot, "ctl", 0660, qpath | Qsctl, &sctl_ops, NULL, xs))
		goto error;

	if (!create_file(sroot, "argv", 0660, qpath | Qargv, &argv_ops, NULL, &xs->argv))
		goto error;

	if (!create_file(sroot, "env", 0660, qpath | Qsenv, &env_ops, NULL, &xs->env))
		goto error;

	if (!create_file(sroot, "stdin", 0660, qpath | Qstdin, &stdin_ops, NULL, xs->stin))
		goto error;

	if (!create_file(sroot, "stdout", 0440, qpath | Qstdout, &stdout_ops, NULL, xs->stout))
		goto error;

	if (!create_file(sroot, "stderr", 0440, qpath | Qstderr, &stderr_ops, NULL, xs->sterr))
		goto error;

	if (!create_file(sroot, "stdio", 0660, qpath | Qstdio, &stdio_ops, NULL, xs->stin))
		goto error;

	if (!create_file(sroot, "wait", 0440, qpath | Qwait, &wait_ops, NULL, NULL))
		goto error;

	if (!create_file(sroot, "id", 0440, qpath | Qid, &id_ops, NULL, NULL))
		goto error;

	if (!create_file(sroot, "ns", 0660, qpath | Qns, &ns_ops, NULL, &xs->ns))
		goto error;

	xs->fsdir = create_file(sroot, "fs", 0770, qpath | Qfs, NULL, NULL, xs);
	if (!xs->fsdir)
		goto error;

	return 1;

error:
	session_remove_dir(xs);
	return 0;
}

static void
session_remove_dir(Xsession *xs)
{
	Spfile *f, *f1, *sroot;

	sroot = xs->sroot;
	if (root->dirfirst == sroot)
		root->dirfirst = sroot->next;
	else
		sroot->prev->next = sroot->next;

	if (sroot->next)
		sroot->next->prev = sroot->prev;

	if (sroot == root->dirlast)
		root->dirlast = sroot->prev;

	sroot->prev = sroot->next = sroot->parent = NULL;

	// remove the children
	f = sroot->dirfirst;
	sroot->dirfirst = sroot->dirlast = NULL;
	while (f != NULL) {
		f1 = f->next;
		spfile_decref(f->parent);
		spfile_decref(f);
		f = f1;
	}
}

static void
session_wipe(Xsession *xs)
{
	int n;
	Spreq *req;
	Spfcall *rc;
	Xwaitreq *wreq, *wreq1;

//	fprintf(stderr, "session_wipe %p\n", xs);
	if (xs->state == Wiped)
		return;

	xs->state = Wiped;
	session_remove_dir(xs);
	if (xs->pid != -1)
		kill(xs->pid, SIGTERM);
	wreq = xs->waitreqs;
	xs->waitreqs = NULL;

	/* respond to all pending reads on "wait" */
	while (wreq != NULL) {
		req = wreq->req;
		rc = sp_alloc_rread(req->tcall->count);
		n = cutstr(rc->data, req->tcall->offset, 
			req->tcall->count, xs->exitstatus, 0);
		sp_set_rread_count(rc, n);
		sp_respond(req, rc);
		wreq1 = wreq->next;
		free(wreq);
		wreq = wreq1;
	}
}

int
session_incref(Xsession *xs)
{
	int ret;

//	fprintf(stderr, "session_incref refcount %d\n", xs->refcount + 1);
	ret = ++xs->refcount;

	return ret;
}

void
session_decref(Xsession *xs)
{
	int wipe;
	Spfile *sroot;

//	fprintf(stderr, "session_decref refcount %d\n", xs->refcount - 1);
	sroot = xs->sroot;
	xs->refcount--;
	if (xs->refcount)
		return;

//	fprintf(stderr, "session_decref xs %p file refcount %d\n", xs, xs->file->refcount);
	wipe = !xs->refcount && xs->mode==Normal && xs->state != Running;
	if (wipe) 
		session_wipe(xs);

	spfile_decref(sroot);
}

static int
rchown(char *path, Spuser *user)
{
	DIR *d;
	struct dirent *de;
	struct stat st;
	char *fn;

	if (chown(path, user->uid, user->dfltgroup->gid) < 0) {
		sp_uerror(errno);
		return -1;
	}

	if (stat(path, &st) < 0) {
		sp_uerror(errno);
		return -1;
	}

	if (!S_ISDIR(st.st_mode))
		return 0;

	d = opendir(path);
	if (!d) {
		sp_uerror(errno);
		return -1;
	}

	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.' && (de->d_name[1] == '.' || de->d_name[1] == '\0'))
			continue;

		fn = sp_malloc(strlen(path) + strlen(de->d_name) + 2);
		if (!fn) {
			closedir(d);
			return -1;
		} 

		sprintf(fn, "%s/%s", path, de->d_name);
		if (rchown(fn, user) < 0) {
			free(fn);
			closedir(d);
			return -1;
		}

		free(fn);
	}

	closedir(d);
	return 0;
}

static int
session_wstat(Spfile *f, Spstat *st)
{
	int ret;
	char *uname;
	Spuser *user;
	Spfile *c;
	Spuserpool *up;
	Xsession *xs;
	uid_t suid;
	gid_t sgid;

	xs = f->aux;
	up = srv->upool;
	user = NULL;
	if (st->uid.len) {
		uname = sp_strdup(&st->uid);
		if (!uname) {
			user = up->uname2user(up, uname);
			free(uname);
		}
	} else if (st->n_uid != ~0) {
		user = up->uid2user(up, st->n_uid);
	}

	if (!user) {
		sp_werror("invalid user", EIO);
		return 0;
	}

	f->uid = user;
	f->gid = user->dfltgroup;
	for(c = f->dirfirst; c != NULL; c = c->next) {
		if (c->uid)
			sp_user_decref(c->uid);

		if (c->muid)
			sp_user_decref(c->muid);

		if (c->gid)
			sp_group_decref(c->gid);

		sp_user_incref(user);
		c->uid = c->muid = user;

		if (user->dfltgroup) {
			sp_group_incref(user->dfltgroup);
			c->gid = user->dfltgroup;
		} else
			c->gid = NULL;
	}

	suid = geteuid();
	sgid = getegid();
	ret = 0;
	if (sameuser || !setreuid(0, 0)) {
		ret = rchown(xs->dirpath, user) != -1;
		setreuid(suid, sgid);
	}

	return ret;
}

static Spfile *
create_file(Spfile *parent, char *name, u32 mode, u64 qpath, void *ops, 
	Spuser *usr, void *aux)
{
	Spfile *ret;

	ret = spfile_alloc(parent, name, mode, qpath, ops, aux);
	if (!ret)
		return NULL;

	if (parent) {
		if (parent->dirlast) {
			parent->dirlast->next = ret;
			ret->prev = parent->dirlast;
		} else
			parent->dirfirst = ret;

		parent->dirlast = ret;
		if (!usr)
			usr = parent->uid;
	}

	if (!usr)
		usr = user;

	ret->atime = ret->mtime = time(NULL);
	ret->uid = ret->muid = usr;
	sp_user_incref(usr);
	sp_user_incref(usr);
	ret->gid = usr->dfltgroup;
	ret->length = 0;
	sp_group_incref(usr->dfltgroup);
	spfile_incref(ret);
	return ret;
}

static void
archinit()
{
	int n;
	struct utsname u;
	char *m, *buf;
	char *ppc = "powerpc";

	uname(&u);
	if (strncmp(u.machine, "Power", 5) == 0)
		m = ppc;
	else
		m = u.machine;

	n = strlen(m) + strlen(u.sysname) + 3;
	buf = malloc(n);
	snprintf(buf, n, "/%s/%s\n", u.sysname, m);

	bufwrite(&archbuf, 0, strlen(buf), (u8 *) buf);
	free(buf);
}

static void
envinit()
{
	int n;
	char *s, **e;

	for(n = 0, e = environ; *e != NULL; e++) {
		s = quotestrdup(*e);
		if (!s)
			return;

		n += bufwrite(&envbuf, n, strlen(s), (u8 *) s);
		n += bufwrite(&envbuf, n, 1, (u8 *) "\n");
		free(s);
	}
}

static void
fsinit()
{
	archinit();
	envinit();

	root = spfile_alloc(NULL, "", 0555 | Dmdir, Qroot, &root_ops, NULL);
	root->parent = root;
	spfile_incref(root);
	root->atime = root->mtime = time(NULL);
	root->uid = root->muid = user;
	sp_user_incref(user);
	sp_user_incref(user);
	root->gid = user->dfltgroup;
	sp_group_incref(user->dfltgroup);

	create_file(root, "clone", 0444, Qclone, &clone_ops, NULL, NULL);
	create_file(root, "ctl", 0664, Qctl, &ctl_ops, NULL, NULL);
	create_file(root, "arch", 0444, Qarch, &fbuf_ops, NULL, &archbuf);
	create_file(root, "env", 0664, Qenv, &fbuf_ops, NULL, &envbuf);
	create_file(root, "procs", 0444, Qprocs, &procs_ops, NULL, NULL);
	create_file(root, "state", 0664, Qstate, &state_ops, NULL, &statebuf);
	create_file(root, "passkey", 0444, Qpkey, &pkey_ops, NULL, NULL);
	create_file(root, "pwent", 0440, Qpwent, &pwent_ops, NULL, NULL);
	create_file(root, "grent", 0440, Qgrent, &grent_ops, NULL, NULL);
	create_file(root, "ns", 0664, Qglobns, &globns_ops, NULL, &nsbuf);
}

static Spfile*
dir_first(Spfile *dir)
{
	spfile_incref(dir->dirfirst);
	return dir->dirfirst;
}

static Spfile*
dir_next(Spfile *dir, Spfile *prevchild)
{
	spfile_incref(prevchild->next);
	return prevchild->next;
}


static int
clone_openfid(Spfilefid *fid)
{
	Xsession *xs;

	xs = session_create(fid->fid->conn->msize);
	if (!xs)
		return 0;

	if (!session_add_dir(xs, fid->fid->user))
		return 0;

	//fprintf(stderr, "clone_openfid sref %d\n", xs->file->refcount);
	fid->aux = xs->sroot;
	return 1;
}

static int
env_openfid(Spfilefid *fid)
{
	Spfile *file, *parent;
	Xsession *xs;

	file = fid->file;
	if(!file)
		return 0;

	parent = file->parent;

	xs = parent->aux;

	if (!xs)
		return 0;

	/* set the length to the saved length of env */
	file->length = xs->env.size;

	return 1;
}

static void
clone_closefid(Spfilefid *fid) {
	Spfile *session;
	Xsession *xs;

	session = fid->aux;
	if(!session)
		return;

	xs = session->aux;
	session_decref(xs);
}

static int
clone_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	Xsession *xs;
	char buf[32];

	xs = ((Spfile *) fid->aux)->aux;
	snprintf(buf, sizeof buf, "%d", xs->sid);

	return cutstr(data, offset, count, buf, 0);
}

static int 
clone_wstat(Spfile *f, Spstat *st) {
	char *uname, *gname;
	Spuser *user;
	Spgroup *group;
	Spuserpool *up;

	up = srv->upool;
	user = NULL;
	group = NULL;
	if (st->uid.len) {
		uname = sp_strdup(&st->uid);
		user = up->uname2user(up, uname);
		free(uname);
		if (!user) {
			sp_werror("invalid user", EIO);
			return 0;
		}
	}

	if (st->n_uid != ~0) {
		if (user)
			sp_user_decref(f->uid);

		user = up->uid2user(up, st->n_uid);
		if (!user) {
			sp_werror("invalid user", EIO);
			return 0;
		}
	}

	if (user) {
		if (f->uid)
			sp_user_decref(f->uid);
		f->uid = user;
	}

	if (st->gid.len) {	
		gname = sp_strdup(&st->gid);
		group = up->gname2group(up, gname);
		free(gname);
		if (!group) {
			sp_werror("invalid group", EIO);
			return 0;
		}
	}

	if (st->n_gid != ~0) {
		if (group)
			sp_group_decref(group);

		group = up->gid2group(up, st->n_gid);
		if (!group) {
			sp_werror("invalid group", EIO);
			return 0;
		}
	}

	if (group) {
		if (f->gid)
			sp_group_decref(f->gid);
		f->gid = group;
	}

	if (st->mode != ~0)
		f->mode = st->mode & 0777;

	return 1;
}

static int
procs_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	char *p;

	p = fid->aux;
	return cutstr(data, offset, count, p, 0);
}

static int
procs_write(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	sp_werror("not implemented", EIO);
	return 0;
}

static int
procs_openfid(Spfilefid *fid)
{
	fid->aux = getprocs();
	if (!fid->aux) {
		sp_werror("unable to read proc list", EIO);
		return 0;
	}

	return 1;
}

static void
procs_closefid(Spfilefid *fid)
{
	free(fid->aux);
}

static int
execute_command(Spuserpool *up, char *s)
{
	int n, ret, nargs, pid, euid;
	char **args, *cmd, **toks, *p;

	nargs = tokenize(s, &toks);
	if (nargs < 0) {
		sp_werror("invalid format", EIO);
		return -1;
	}

	cmd = toks[0];
	args = &toks[1];

	ret = -1;
	if (strcmp("user-add", cmd) == 0) {
		if (nargs != 5) {
			sp_werror("Usage: user-add uname uid groupname key", EIO);
			goto done;
		}

		n = strtol(args[1], &p, 10);
		if (*p != '\0') {
			sp_werror("invalid user id", EIO);
			goto done;
		}

		if (!ukey_add(up, args[0], n, args[2], args[3], strlen(args[3])))
			ret = 1;
	} else if (strcmp("user-del", cmd) == 0) {
		if (!ukey_del(up, args[0]))
			ret = 1;
	} else if (strcmp("user-flush", cmd) == 0) {
		if (!ukey_flush(up))
			ret = 1;
	} else if (strcmp("user-add-group", cmd) == 0) {
		if (!ukey_add_group(up, args[0], args[1]))
			ret = 1;
	} else if (strcmp("user-del-group", cmd) == 0) {
		if (!ukey_del_group(up, args[0], args[1]))
			ret = 1;
	} else if (strcmp("group-add", cmd) == 0) {
		if (nargs != 3) {
			sp_werror("Usage: group-add groupname gid", EIO);
			goto done;
		}

		n = strtol(args[1], &p, 10);
		if (*p != '\0') {
			sp_werror("invalid group id %s", EIO, args[1]);
			goto done;
		}

		if (!group_add(up, args[0], n))
			ret = 1;
	} else if (strcmp("group-del", cmd) == 0) {
		if (!group_del(up, args[0]))
			ret = 1;
	} else if (strcmp("group-flush", cmd) == 0) {
		if (!group_flush(up))
			ret = 1;
	} else if (strcmp("kill", cmd) == 0) {
		n = signame2signo(args[0]);
		if (n < 0) {
			sp_werror("unsupported signal", EIO);
			goto done;
		}

		pid = strtol(args[1], &p, 10);
		if (*p != '\0') {
			sp_werror("invalid pid", EIO);
			goto done;
		}

		if ((seteuid(0) || kill(pid, n)) < 0) {
			sp_uerror(errno);
		        seteuid(euid);
			goto done;
		}

		seteuid(euid);
		ret = 1;
	} else {
		sp_werror("unknown command", EIO);
	}

done:
	free(toks);
	return ret;
}

static int
ctl_write(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	int len, i, n;
	char *s, *p;
	Spuserpool *up;

	up = fid->fid->conn->srv->upool;
	len = ctlbuf?strlen(ctlbuf):0;
	s = realloc(ctlbuf, len + count + 1);
	if (!s) {
		sp_werror(Enomem, ENOMEM);
		return -1;
	}

	ctlbuf = s;
	memmove(ctlbuf + len, data, count);
	ctlbuf[len + count] = '\0';

	i = 0;
	while ((p = strchr(ctlbuf + i, '\n')) != NULL) {
		*p = '\0';
		n = execute_command(up, ctlbuf + i);
		i = (p - ctlbuf) + 1;

		if (n < 0) {
			free(ctlbuf);
			ctlbuf = NULL;
			return -1;
		}
	}

	if (ctlbuf[i] == '\0') {
		free(ctlbuf);
		ctlbuf = NULL;
	} else if (i > 0)
		memmove(ctlbuf, ctlbuf + i, strlen(ctlbuf + i) + 1);

	return count;
}

static int 
ctl_wstat(Spfile *f, Spstat *st) {
	Xsession *xs;

	xs = f->parent->aux;
	if (st->length == 0) {
		free(xs->ctl);
		xs->ctl = NULL;

		return 1;
	}

	sp_werror("unsupported operation", EPERM);
	return 0;
}

static char *
envmatch(char *key, int keylen, char **envtok)
{
	int i, l;
	char *s;

	for(i = 0; envtok[i] != NULL; i++) {
		s = envtok[i];
		l = strlen(s);
		if (l<keylen || s[keylen]!='=')
			continue;

		if (!memcmp(key, s, keylen))
			return &s[keylen + 1];
	}

	return NULL;
}

static char *
envreplace(char *str, int slen, char **envtok)
{
	char *s, *p, *v, b;
	Xfilebuf buf;

	s = str;
	bufinit(&buf);
	while ((p = strchr(s, '$')) != NULL) {
		bufwrite(&buf, buf.size, p-s, s);
		s = p + 1;
		for(p = s; isalnum(*p); p++)
			;

		v = envmatch(s, p-s, envtok);
		if (v)
			bufwrite(&buf, buf.size, strlen(v), v);
		else
			bufwrite(&buf, buf.size, p-s+1, s-1);

		s = p;
	}

	bufwrite(&buf, buf.size, (slen + str - s), s);
	b = 0;
	bufwrite(&buf, buf.size, 1, &b);

	/* this is a bit ugly, but saves one more malloc */
	return buf.buf;
}

static int
isdir(const char *path)
{
	struct stat buf;
	if (stat(path, &buf) < 0)
		return -1;
	if (! S_ISDIR(buf.st_mode))
		return -1;
	return 0;
}
static int
xnamespace(Xsession *xs, char **envtok)
{
	int i, n;
	char opts[128], **toks;
	char *addr, *port, *p, *ep, *s, *ns;

	ns = envreplace(xs->ns.buf, xs->ns.size, envtok);
	p = ns;
	ep = ns + strlen(ns);
	toks = NULL;

	/* Temporarily gain privileges, just in case */
	if(setuid(0) < 0)
		goto error;

	while (p < ep) {
		s = strchr(p, '\n');
		if (!s)
			s = ep;

		*s = 0;
		n = tokenize(p, &toks);
		if (n < 0)
			goto error;
		else if (n == 0) {
			free(toks);
			continue;
		}

		p = s + 1;
		if (!strcmp(toks[0], "unshare")) {
			if (unshare(CLONE_FS|CLONE_NEWNS) < 0) {
				sp_uerror(errno);
				return -1;
			}
		} else if (!strcmp(toks[0], "mount")) {
			/* 'mount' src dest type opts */
			if (n != 5) {
				sp_werror("invalid mount arguments", EIO);
				goto error;
			}
			if (debuglevel)
				fprintf(stderr, "Mount %s %s %s 0 %s\n", 
					toks[1], toks[2], toks[3], toks[4]);
			if (mount(toks[1], toks[2], toks[3], 0, toks[4]) < 0) {
				sp_uerror(errno);
				goto error;
			}
		} else if (!strcmp(toks[0], "bind")) {
			/* 'bind' src dest */
			if (n != 3) {
				sp_werror("invalid bind arguments", EIO);
				goto error;
			}
/*
			if (!isdir(toks[1])){
				fprintf(stderr, "Access failed for %s\n", toks[1]);
				sp_uerror(errno);
				goto error;
			}
			if (!isdir(toks[2])){
				fprintf(stderr, "Access failed for %s\n", toks[2]);
				sp_uerror(errno);
				goto error;
			}
 */
			if (debuglevel)
				fprintf(stderr, "Bind %s %s NULL MS_BIND NULL\n", 
						toks[1], toks[2]);
			if (mount(toks[1], toks[2], NULL, MS_BIND, NULL) < 0) {
				sp_uerror(errno);
				goto error;
			}
		} else if (!strcmp(toks[0], "import")) {
			/* 'import' addr!port dest */
			if (n != 3) {
				sp_werror("invalid import arguments", EIO);
				goto error;
			}

			snprintf(opts, sizeof(opts), "access=any,msize=32792");
			addr = toks[1];
			port = strchr(addr, '!');
			if (port) {
				i = strlen(opts);
				snprintf(opts+i, sizeof(opts)-i-1, ",port=%s", port+1);
				*port = '\0';
			}

			if (debuglevel)
				fprintf(stderr, "Import %s %s \"9p\" 0 %s NULL\n", 
					addr, toks[2], opts);
			if (mount(addr, toks[2], "9p", 0, opts) < 0) {
				sp_uerror(errno);
				goto error;
			}
		} else if (!strcmp(toks[0], "cd")) {
			if (debuglevel)
				fprintf(stderr, "cd %s\n", toks[1]);
			/* 'cd' dir */
			if (chdir(toks[1]) < 0) {
				sp_uerror(errno);
				goto error;
			}
		} else if (!strcmp(toks[0], "chroot")) {
			/* 'chroot' dir */
			if (debuglevel)
				fprintf(stderr, "chroot %s\n", toks[1]);
			if (chroot(toks[1]) < 0) {
				sp_uerror(errno);
				goto error;
			}
		} else {
			fprintf(stderr, "namespace: invalid operation %s\n", toks[0]);
			sp_werror("invalid operation", EIO);
			goto error;
		}

		free(toks);
		toks = NULL;
	}

	/* We are done, drop the privileges now */
	if(setuid(getuid()) < 0)
		goto error;	

	free(ns);
	return 0;

error:
	free(ns);
	free(toks);
	return -1;
}

static int
xexec(Xsession *xs, char *exec)
{
	int pid;
	int ifd, ofd, efd;
	char *argv, *env;
	char **argvtok, **envtok;
	int pip[2];
	char buf, *xcpuids;
	Xsession *s;

	ifd = -1;
	ofd = -1;
	efd = -1;
	if (!exec) {
		sp_werror("executable not found", EIO);
		return 0;
	}

	if (xs->state == Wiped) {
		sp_werror("session wiped", EIO);
		return 0;
	}

	xcpuids = sp_malloc(strlen(xs->ctlreq->conn->address) + 256);
	if (!xcpuids)
		return 0;

	sprintf(xcpuids, "\nXCPUSID=%d\nXCPUID=%s/%d\nXCPU_PARENT=%s",
		xs->sid, xs->gid, xs->lid, xs->ctlreq->conn->address);
	bufwrite(&xs->env, xs->env.size, strlen(xcpuids), xcpuids);
	free(xcpuids);
	
	env = sp_malloc(xs->env.size + 1);
	if (!env)
		return 0;
	memmove(env, xs->env.buf, xs->env.size);
	env[xs->env.size] = '\0';
  if (debuglevel)
  {
	  printf("Received environment variables :\n");
	  printf("%s\n", env);
  }
	if (tokenize(env, &envtok) < 0) {
		sp_werror("environment bad format", EIO);
		return 0;
	}

	argv = sp_malloc(xs->argv.size + 1);
	if (!argv)
		return 0;
	memmove(argv, xs->argv.buf, xs->argv.size);
	argv[xs->argv.size] = '\0';
	if (tokenize(argv, &argvtok) < 0) {
		sp_werror("arguments bad format", EIO);
		return 0;
	}

	if (pipe(pip) < 0) {
		sp_uerror(errno);
		return 0;
	}

	if (xs->stinfname) {
		ifd = open(xs->stinfname, O_RDONLY);
		if (ifd < 0) {
			sp_uerror(errno);
			goto error;
		}
	} else
		ifd = xs->stin->rfd;

	if (xs->stoutfname) {
		ofd = open(xs->stoutfname, O_WRONLY);
		if (ofd < 0) {
			sp_uerror(errno);
			goto error;
		}
	} else
		ofd = xs->stout->rfd;

	if (xs->sterrfname) {
		if (xs->stoutfname && strcmp(xs->stoutfname, xs->sterrfname) == 0)
			efd = ofd;
		else {
			efd = open(xs->sterrfname, O_WRONLY);
			if (ofd < 0) {
				sp_uerror(errno);
				goto error;
			}
		}
	} else
		efd = xs->sterr->rfd;

	pid = fork();
	if (pid == -1) {
		sp_suerror("cannot fork: %s", errno);
		return 0;
	} else if (pid == 0) {
		/* child */

		/* close the file descriptors for all other sessions */
		for(s = sessions; s != NULL; s = s->next) {
			if (xs == s)
				continue;
			if (s->stin) {
				pip_close_remote(s->stin);
				pip_close_local(s->stin);
			}

			if (s->stout) {
				pip_close_remote(s->stout);
				pip_close_local(s->stout);
			}

			if (s->sterr) {
				pip_close_remote(s->sterr);
				pip_close_local(s->sterr);
			}
		}

		if (dup2(ifd, 0) < 0)
			goto child_error;

		if (dup2(ofd, 1) < 0)
			goto child_error;

		if (dup2(efd, 2) < 0)
			goto child_error;

		if (xnamespace(xs, envtok) < 0) {
			perror("xnamespace failed: ");
			exit(errno);
		}

		close(pip[1]);
		read(pip[0], &buf, 1);
		close(pip[0]);

		execve(exec, argvtok, envtok);
child_error:
		perror("");
		exit(errno);
	}

	/* parent */
	xs->state = Running;
	free(envtok);
	free(argvtok);
	free(env);
	free(argv);
	session_incref(xs);
	if (xs->stin)
		pip_close_remote(xs->stin);
	else
		close(ifd);

	if (xs->stout)
		pip_close_remote(xs->stout);
	else
		close(ofd);

	if (xs->sterr)
		pip_close_remote(xs->sterr);
	else
		close(efd);

	xs->pid = pid;
	close(pip[0]);
	buf = 5;
	write(pip[1], &buf, 1);
	close(pip[1]);
	return 1;

error:
	close(ifd);
	close(ofd);
	close(efd);
	return 0;
}

static int
session_set_id(Xsession *xs, char *id)
{
	int lid;
	char *gid, *p, *t;

	gid = NULL;
	lid = -1;

	p = strchr(id, '/');
	if (p) {
		*p = '\0';
		p++;

		if (*p != '\0') {
			lid = strtol(p, &t, 10);
			if (*t != '\0') {
				sp_werror("syntax error", EIO);
				return 0;
			}

			if (lid < 0) {
				sp_werror("negative id not permitted", EIO);
				return 0;
			}
		}
	}

	if (*id != '\0') {
		free(xs->gid);
		xs->gid = strdup(id);
	}

	if (lid >= 0)
		xs->lid = lid;

	return 1;
}

static int
connauth(Spcfid *afid, Spuser *user, void *aux)
{
	int n;
	char buf[1024], hash[64];
	char *pkey;

	pkey = aux;
	if (!pkey)
		return 0;

	n = spc_read(afid, (u8 *) buf, sizeof(buf), 0);
	if (n < 0)
		return -1;

	memmove(buf + n, pkey, strlen(pkey));
	n = xauth_hash((u8 *) buf, n + strlen(pkey), (u8 *) hash, sizeof(hash));
	if (n < 0)
		return -1;

	n = spc_write(afid, (u8 *) hash, n, 0);
	if (n < 0) 
		return -1;

	return 0;
}

static int
session_connect(Xsession *xs, Spuser *user, char *paddr)
{
	char *addr, *sid, *pkey;

	if (xs->upfs || xs->uprefix) {
		sp_werror("session already connected", EIO);
		return 0;
	}

	addr = strdup(paddr);
	if (!addr) {
		sp_werror(Enomem, ENOMEM);
		return 0;
	}

	sid = strchr(addr, '/');
	if (!sid) {
		sp_werror("syntax error", EIO);
		goto error;
	}
	*sid = '\0';
	sid++;

	pkey = strchr(sid, ':');
	if (pkey) {
		*pkey = '\0';
		pkey++;
	}

	xs->upfs = spc_netmount(addr, user, XCPU_PORT, connauth, pkey);
	if (!xs->upfs)
		goto error;

	xs->uprefix = strdup(sid);
	free(addr);
	return 1;

error:
	free(addr);
	return 0;
}

static int
execute_session_command(Xsession *xs, Spuser *user, char *s)
{
	int n, ret, nargs;
	char *buf, **toks, *cmd, **args;

	nargs = tokenize(s, &toks);
	if (nargs < 0) {
		sp_werror("invalid format", EIO);
		return 0;
	}

	cmd = toks[0];
	args = &toks[1];

	ret = 0;
	if (strcmp("exec", cmd) == 0) {
//		chmod(xs->execpath, 0500);
		if (!args[0]) {
			sp_werror("too few arguments", EIO);
			goto done;
		}

		ret = xexec(xs, args[0]);
	} else if (strcmp("connect", cmd) == 0) {
		if (!args[0]) {
			sp_werror("too few arguments", EIO);
			goto done;
		}

		ret = session_connect(xs, user, args[0]);
	} else if (strcmp("wipe", cmd) == 0) {
		session_wipe(xs);
		ret = 1;
	} else if (strcmp("signal", cmd) == 0) {
		n = signame2signo(args[0]);
		if (n < 0) {
			sp_werror("unsupported signal", EIO);
			goto done;
		}

		if (xs->pid != -1)
			kill(xs->pid, n);
		ret = 1;
	} else if (strcmp("type", cmd) == 0) {
		n = Normal;
		if (strcmp("normal", args[0]) == 0)
			n = Normal;
		else if (strcmp("persistent", args[0]) == 0)
			n = Persistent;
		else {
			sp_werror("invalid session type", EIO);
			goto done;
		}

		xs->mode = n;
		ret = 1;
	} else if (strcmp("close", cmd) == 0) {
		if (strcmp(args[0], "stdin") == 0) {
			pip_close_local(xs->stin);
		} else if (strcmp(args[0], "stdout") == 0) {
			pip_close_local(xs->stout);
		} else if (strcmp(args[0], "stderr") == 0) {
			pip_close_local(xs->sterr);
		} else {
			sp_werror("invalid argument", EIO);
			goto done;
		}

		ret = 1;
	} else if (strcmp("id", cmd) == 0) {
		if (args[0] == NULL) {
			sp_werror("argument expected", EIO);
			goto done;
		}

		ret = session_set_id(xs, args[0]);
	} else if (strcmp("redirect", cmd) == 0) {
		if (!args[0] || !args[1]) {
			sp_werror("too few arguments", EIO);
			goto done;
		}

		buf = strdup(args[1]);

		if (strcmp(args[0], "stdin"))
			xs->stinfname = buf;
		else if (strcmp(args[0], "stdout"))
			xs->stoutfname = buf;
		else if (strcmp(args[0], "stdout"))
			xs->sterrfname = buf;
		else {
			free(buf);
			sp_werror("invalid stream", EIO);
			goto done;
		}

		ret = 1;
	} else {
		sp_werror("unknown command", EIO);
	}

done:
	free(toks);
	return ret;
}

static int
sctl_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	Xsession *xs;
	char buf[16];

	xs = fid->file->parent->aux;
	snprintf(buf, sizeof buf, "%d", xs->pid);

	return cutstr(data, offset, count, buf, 0);
}

void
sctl_execute_commands(Xsession *xs, Spuser *user)
{
	int n, ecode;
	char *p, *ename;
	Spfcall *fc;

	if (!xs->ctlreq)
		return;

	while ((p = strchr(xs->ctl + xs->ctlpos, '\n')) != NULL) {
		*p = '\0';
		n = execute_session_command(xs, user, xs->ctl + xs->ctlpos);
		xs->ctlpos = (p - xs->ctl) + 1;

		if (n < 0)
			return;
		if (!n) {
			sp_rerror(&ename, &ecode);
			if (ename == Enomem) 
				fc = sp_srv_get_enomem(xs->ctlreq->conn->srv, xs->ctlreq->conn->dotu);
			else
				fc = sp_create_rerror(ename, ecode, xs->ctlreq->conn->dotu);
			sp_werror(NULL, 0);
			goto done;
		}
	}

	if (xs->ctl[xs->ctlpos] == '\0') {
		free(xs->ctl);
		xs->ctl = NULL;
		xs->ctlpos = 0;
		n = xs->ctlreq->tcall->count;
	} else if (xs->ctlpos > 0) {
		memmove(xs->ctl, xs->ctl + xs->ctlpos, strlen(xs->ctl + xs->ctlpos) + 1);
		xs->ctlpos = 0;
		n = xs->ctlreq->tcall->count - strlen(xs->ctl);
		if (n < 0) 
			n = xs->ctlreq->tcall->count;
	}

	fc = sp_create_rwrite(n);

done:
	sp_respond(xs->ctlreq, fc);
	xs->ctlreq = NULL;
	xs->ctlpos = 0;
}

static int
sctl_write(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	int len;
	char *s;
	Xsession *xs;

	xs = fid->file->parent->aux;
	if (xs->ctlreq) {
		sp_werror("cannot write while the session is cloning", EIO);
		return -1;
	}

	len = xs->ctl?strlen(xs->ctl):0;
	s = realloc(xs->ctl, len + count + 1);
	if (!s) {
		sp_werror(Enomem, ENOMEM);
		return -1;
	}

	xs->ctl = s;
	memmove(xs->ctl + len, data, count);
	xs->ctl[len + count] = '\0';

	xs->ctlreq = req;
	xs->ctlpos = 0;
	sctl_execute_commands(xs, fid->fid->user);

	return -1;
}

static int 
sctl_wstat(Spfile *f, Spstat *st) {
	Xsession *xs;

	xs = f->parent->aux;
	if (st->length == 0) {
		free(xs->ctl);
		xs->ctl = NULL;

		return 1;
	}

	sp_werror("unsupported operation", EPERM);
	return 0;
}

static int
stdio_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	Xsession *xs;

	xs = fid->file->parent->aux;
	return pip_addreq(xs->stout, req)?-1:0;
}

static int
stdio_write(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	Xsession *xs;

	xs = fid->file->parent->aux;
	return pip_addreq(xs->stin, req)?-1:0;
}

static int 
wait_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	int n;
	Xwaitreq *wreq;
	Xsession *xs;

	xs = fid->file->parent->aux;
	if (xs->state==Finished || xs->state==Wiped) {
		n = cutstr(data, offset, count, xs->exitstatus, 0);
		return n;
	}

	wreq = malloc(sizeof(*wreq));
	if (!wreq) {
		sp_werror(Enomem, ENOMEM);
		return 0;
	}

	wreq->req = req;
	wreq->next = xs->waitreqs;
	xs->waitreqs = wreq;
	return -1;
}

static int 
id_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	int n;
	char *buf;
	Xsession *xs;

	xs = fid->file->parent->aux;
	buf = sp_malloc(strlen(xs->gid) + 32);
	if (!buf)
		return -1;

	sprintf(buf, "%s/%d", xs->gid, xs->lid);
	n = cutstr(data, offset, count, buf, 0);
	free(buf);

	return n;
}

static int
wait_flush(Xsession *xs, Spreq *req)
{
	Xwaitreq *wreq, *pwreq;

	for(pwreq = NULL, wreq = xs->waitreqs; wreq != NULL; pwreq = wreq, wreq = wreq->next)
		if (wreq->req == req) {
			if (pwreq)
				pwreq->next = wreq->next;
			else
				xs->waitreqs = wreq->next;

			free(wreq);
			return 1;
		}

	return 0;
}

static int
pkey_openfid(Spfilefid *fid)
{
	return 1;
}

static void
pkey_closefid(Spfilefid *fid)
{
}

static int
pkey_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	int n;
	char buf[1024];

	n = pkey_gen(fid->fid->user, buf, sizeof(buf));
	if (n < 0)
		return -1;

	return cutbuf(data, offset, count, buf, 0, n);
}

static int
pwent_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	char *buf;
	int ret, boff, blen, i;
	Spuser *user;
	
	boff = 0;
	ret = 0;

	user = sp_priv_user_list(srv->upool);
	if (!user) {
		sp_werror("userpool empty: no users", EIO);
		return 0;
	}

	for (; user != NULL; user = user->next) {
		blen = strlen(user->uname) + 12; /* uname:uid:gid */

		for(i=0; i < user->ngroups; i++)
			blen += strlen(user->groups[i]->gname)+1;

		blen += 2; /* \n\0 */
		buf = sp_malloc(blen);
		if (!buf)
			return -1;

		sprintf(buf, "%s:%u:%u", user->uname, user->uid, 
			user->dfltgroup?user->dfltgroup->gid:0);

		for(i=0; i < user->ngroups; i++) {
			strcat(buf, i?",":":");
			strcat(buf, user->groups[i]->gname);
		}		
		strcat(buf, "\n");
		blen = strlen(buf);
		ret =+ cutbuf(data, offset, count, buf, boff, blen);
		boff += blen;
		free(buf);
	}

	return ret;
}

static int
grent_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	char *buf;
	int ret, boff, blen;
	Spgroup *group;
	
	boff = 0;
	ret = 0;

	group = sp_priv_group_list(srv->upool);
	if (!group) {
		sp_werror("userpool empty: no groups", EIO);
		return 0;
	}		

	for (; group != NULL; group = group->next) {
		blen = strlen(group->gname) + 8; /* gname:gid\n\0 */
		buf = sp_malloc(blen);
		if (!buf)
			return -1;
		snprintf(buf, blen, 
			 "%s:%u\n", group->gname, group->gid);
		blen = strlen(buf);
		ret =+ cutbuf(data, offset, count, buf, boff, blen);
		boff += blen;
		free(buf);
	}

	return ret;
}

static void
reftrack_ref(Spfile *file, Spfilefid *fid)
{
	Xsession *xs;

	if ((file->qid.path&QMASK) == 0)
		xs = file->aux;
	else
		xs = file->parent->aux;

	//fprintf(stderr, "reftrack_ref %s %d sref %d\n", file->name, file->refcount, xs->file->refcount);
	//fprintf(stderr, "reftrack_ref %s sroot %p %d\n", file->name, xs->sroot, xs->sroot->refcount);
	session_incref(xs);
}

static void 
reftrack_unref(Spfile *file, Spfilefid *fid)
{
	Xsession *xs;

	if ((file->qid.path&QMASK) == 0)
		xs = file->aux;
	else
		xs = file->parent->aux;

	//fprintf(stderr, "reftrack_unref %s %d sref %d\n", file->name, file->refcount-1, xs->file->refcount);
	//fprintf(stderr, "reftrack_unref %s sroot %p %d\n", file->name, xs->sroot, xs->sroot->refcount);
	session_decref(xs);
}

void
usage()
{
	fprintf(stderr, "xcpufs: -h -d -s -m msize -p port -t tmpdir -a auth-file-name (e.g. /etc/xpuc/admin_key.pub)\n");
	exit(-1);
}

static Spfcall *
xflush(Spreq *req)
{
	int n;
	Xsession *xs;
	Spfilefid *fid;
	Spfile *f;

	n = 0;
	if (!req->fid || !req->fid->aux) {
		n = 1;
		goto done;
	}

	change_user(req->fid->user);
	fid = req->fid->aux;
	f = fid->file;
	xs = f->parent->aux;

	switch (f->qid.path & 255) {
	case Qstdin:
		n = pip_flushreq(xs->stin, req);
		break;

	case Qstdout:
		n = pip_flushreq(xs->stout, req);
		break;

	case Qstderr:
		n = pip_flushreq(xs->sterr, req);
		break;

	case Qstdio:
		if (req->tcall->type == Tread) 
			n = pip_flushreq(xs->stout, req);
		else
			n = pip_flushreq(xs->stin, req);
		break;

	case Qwait:
		n = wait_flush(xs, req);
		break;

	case Qctl:
		n = 1;
		xs->ctlreq = NULL;	/* TODO: real flush */
		break;
	default:
		n = 1;
	}

done:
	if (n) {
		sp_respond(req, NULL);
		return sp_create_rflush();
	} else
		return NULL;
}

static int 
xclone(Spfid *fid, Spfid *newfid)
{
	int ret;
	Spfilefid *f;

	change_user(fid->user);
	f = fid->aux;
	if (f->file)
		ret = spfile_clone(fid, newfid);
	else
		ret = ufs_clone(fid, newfid);

	return ret;
}

static int 
xwalk(Spfid *fid, Spstr *wname, Spqid *wqid)
{
	int ret;
	char *path;
	Spfilefid *f;
	Spfile *file;
	Xsession *xs;
	Fsfid *fsfid;

	change_user(fid->user);
	f = fid->aux;
	if (f->file)
		ret = spfile_walk(fid, wname, wqid);
	else {
		fsfid = f->aux;
		xs = fsfid->xs;
		if (xs) {
			file = xs->fsdir;
			path = xs->dirpath;
		} else {
			sp_werror("internal error", EIO);
			return 0;
		}
 
		if (wname->len==2 && !memcmp(wname->str, "..", 2) 
		&& !strcmp(fsfid->path, path)) { 
			f->file = file;
			spfile_incref(f->file);
			if (fsfid->fd != -1)
				close(fsfid->fd);
			if (fsfid->dir)
				closedir(fsfid->dir);

			free(fsfid->path);
			free(fsfid);
			f->aux = NULL;
			ret = spfile_walk(fid, wname, wqid);
		} else
			ret = ufs_walk(fid, wname, wqid);
	}

	f = fid->aux;
	if (f->file) {
		xs = f->file->aux;
		if (!f->file->ops) {
			spfile_decref(f->file);
			ufs_attach(fid, xs, wqid);
		}
	} 

	return ret;
}

static Spfcall *
xopen(Spfid *fid, u8 mode)
{
	Spfilefid *f;

	change_user(fid->user);
	f = fid->aux;
	if (f->file)
		return spfile_open(fid, mode);
	else
		return ufs_open(fid, mode);
}

static Spfcall *
xcreate(Spfid *fid, Spstr *name, u32 perm, u8 mode, Spstr *extension)
{
	Spfilefid *f;

	change_user(fid->user);
	f = fid->aux;
	if (f->file)
		return spfile_create(fid, name, perm, mode, extension);
	else
		return ufs_create(fid, name, perm, mode, extension);
}

static Spfcall *
xread(Spfid *fid, u64 offset, u32 count, Spreq *req)
{
	Spfilefid *f;

	change_user(fid->user);
	f = fid->aux;
	if (f->file)
		return spfile_read(fid, offset, count, req);
	else
		return ufs_read(fid, offset, count, req);
}

static Spfcall *
xwrite(Spfid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	Spfilefid *f;

	change_user(fid->user);
	f = fid->aux;
	if (f->file)
		return spfile_write(fid, offset, count, data, req);
	else
		return ufs_write(fid, offset, count, data, req);
}

static Spfcall*
xclunk(Spfid *fid)
{
	Spfilefid *f;
	Spfcall *ret;

	change_user(fid->user);
	f = fid->aux;
	if (f->file)
		ret = spfile_clunk(fid);
	else
		ret = ufs_clunk(fid);

	return ret;
}

static Spfcall*
xremove(Spfid *fid)
{
	Spfilefid *f;

	change_user(fid->user);
	f = fid->aux;
	if (f->file)
		return spfile_remove(fid);
	else
		return ufs_remove(fid);
}

static Spfcall*
xstat(Spfid *fid)
{
	Spfilefid *f;

	change_user(fid->user);
	f = fid->aux;
	if (f->file)
		return spfile_stat(fid);
	else
		return ufs_stat(fid);
}

static Spfcall*
xwstat(Spfid *fid, Spstat *stat)
{
	Spfilefid *f;

	change_user(fid->user);
	f = fid->aux;
	if (f->file)
		return spfile_wstat(fid, stat);
	else
		return ufs_wstat(fid, stat);
}

static void 
xfiddestroy(Spfid *fid)
{
	Spfilefid *f;

	/* if this fid is not really there, user may be 0. So don't even try if user is 0 */
	if (fid->user)
		change_user(fid->user);
	f = fid->aux;
	if (!f)
		return;

	if (f->file)
		spfile_fiddestroy(fid);
	else
		ufs_fiddestroy(fid);
}

static void
sigchld_setup_pipe(void)
{
	int pip[2];

	if (pipe(pip) < 0) 
		return;

	fcntl(pip[0], F_SETFD, FD_CLOEXEC);
	fcntl(pip[1], F_SETFD, FD_CLOEXEC);
	spfd_add(pip[0], sigchld_notify, (int *)(long) pip[0]);
	chld_fd = pip[1];
}

static void
sigchld_notify(Spfd *spfd, void *aux)
{
	Xsession *s;
	Xwaitreq *wreq, *wreq1;
	Spreq *req;
	Spfcall *rc;
	int pid, status, n;

	if (!spfd_has_error(spfd))
		return;

//	fprintf(stderr, "sigchld_notify\n");
	close((long) aux);
	spfd_remove(spfd);
	sigchld_setup_pipe();

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);

		if (pid <= 0)
			break;

//		fprintf(stderr, "chld_notify pid %d status %d\n", pid, status);
		for(s = sessions; s != NULL; s = s->next)
			if (s->pid == pid)
				break;

		if (!s)
			continue;

		if (s->state != Wiped)
			s->state = Finished;
		s->pid = -1;
		s->exitstatus = malloc(16);
		if (s->exitstatus) 
			sprintf(s->exitstatus, "%d", status);
		pip_close_local(s->stin);
		wreq = s->waitreqs;
		s->waitreqs = NULL;

		/* respond to all pending reads on "wait" */
		while (wreq != NULL) {
			req = wreq->req;
			rc = sp_alloc_rread(req->tcall->count);
			n = cutstr(rc->data, req->tcall->offset, 
				req->tcall->count, s->exitstatus, 0);
			sp_set_rread_count(rc, n);
			sp_respond(req, rc);
			wreq1 = wreq->next;
			free(wreq);
			wreq = wreq1;
		}

		session_decref(s);
	}
}

static void
sigchld_handler(int sig)
{
//	fprintf(stderr, "sigchld_handler\n");
	if (chld_fd >= 0) {
		close(chld_fd);
		chld_fd = -1;
	}
}

static int
init_unix_users(Spuserpool *up)
{
	int i;
	char buf[1024];
	struct passwd *pw;
	struct group *gr;
	Spuser *user;
	Spgroup *group;
	Xkey *xkey;

	/* create the groups */
	setgrent();
	while ((gr = getgrent()) != NULL) {
		if (!sp_priv_group_add(up, gr->gr_name, gr->gr_gid))
			return -1;
	}
	endgrent();

	/* add the users */
	setpwent();
	while ((pw = getpwent()) != NULL) {
		snprintf(buf, sizeof(buf), "%s/.ssh/id_rsa.pub", pw->pw_dir);
		xkey = xauth_pubkey_create_from_file(buf);
		if (!xkey) {
			sp_werror("No key for user %s", 0, pw->pw_name);
			continue;
		}

		user = sp_priv_user_add(up, pw->pw_name, pw->pw_uid, xkey);
		if (!user)
			return -1;

		group = up->gid2group(up, pw->pw_gid);
		if (!group)
			return -1;

		sp_priv_user_setdfltgroup(user, group);
	}
	endpwent();

	/* add the users to the groups */
	setgrent();
	while ((gr = getgrent()) != NULL) {
		group = up->gid2group(up, gr->gr_gid);
		if (!group)
			return -1;

		for(i = 0; gr->gr_mem[i] != NULL; i++) {
			user = up->uname2user(up, gr->gr_mem[i]);
			if (!user) {
				sp_werror(NULL, 0);
				continue;
			}

			sp_priv_group_adduser(group, user);
		}
	}
	endgrent();

	return 0;	
}

static void
xconnopen(Spconn *conn)
{
	if (conn->srv->debuglevel)
		fprintf(stderr, "connection %p from %s opened\n",
			conn, conn->address);
}

static void
xconnclose(Spconn *conn)
{
	if (conn->srv->debuglevel)
		fprintf(stderr, "connection %p from %s closed\n",
			conn, conn->address);
}

int mkdir_die(char *dir, int mode)
{
	int ret;
	ret = mkdir(dir, mode);
	if ((ret < 0) && (errno != EEXIST)){
		perror(dir);
		return -1;
	}
	return 0;
}
		
static int
nsinit(void)
{
	char buf[1024];
	int ret;

	ret = mkdir_die("/mnt/term", 0775);
	ret |= mkdir_die("/mnt/sandbox", 0775);
	ret |= mkdir_die("/mnt/sandbox/home", 0775);
	ret |= mkdir_die("/mnt/sandbox/dev", 0775);
	ret |= mkdir_die("/mnt/sandbox/proc", 0775);
	ret |= mkdir_die("/mnt/sandbox/sys", 0775);
	if (ret < 0)
		return ret;
	snprintf(buf, sizeof(buf), "unshare\n");
	bufwrite(&nsbuf, nsbuf.size, strlen(buf), buf);
	snprintf(buf, sizeof(buf), "import $XCPUTSADDR /mnt/term\n");
	bufwrite(&nsbuf, nsbuf.size, strlen(buf), buf);
	snprintf(buf, sizeof(buf), "bind /mnt/term/$XCPUARCHDIR /mnt/sandbox\n");
	bufwrite(&nsbuf, nsbuf.size, strlen(buf), buf);
	snprintf(buf, sizeof(buf), "bind /mnt/term/home /mnt/sandbox/home\n");
	bufwrite(&nsbuf, nsbuf.size, strlen(buf), buf);
	snprintf(buf, sizeof(buf), "bind /dev /mnt/sandbox/dev\n");
	bufwrite(&nsbuf, nsbuf.size, strlen(buf), buf);
	snprintf(buf, sizeof(buf), "bind /proc /mnt/sandbox/proc\n");
	bufwrite(&nsbuf, nsbuf.size, strlen(buf), buf);
	snprintf(buf, sizeof(buf), "bind /sys /mnt/sandbox/sys\n");
	bufwrite(&nsbuf, nsbuf.size, strlen(buf), buf);
	snprintf(buf, sizeof(buf), "chroot /mnt/sandbox\n");
	bufwrite(&nsbuf, nsbuf.size, strlen(buf), buf);
	return ret;
}

int 
main(int argc, char *argv[])
{
	int c, ecode;
	int port;
	int msize;
	int nokeys;
	pid_t pid;
	char *s, *ename, mntopts[128];
	char *afname;
	struct sigaction sact;
	Spuserpool *upool;
	struct passwd *xcpu_admin;
	gid_t xcpu_gid;
	uid_t xcpu_uid;

	msize = 32768 + IOHDRSZ;
	spc_chatty = 1;
	port = XCPU_PORT;
	afname = "/etc/xcpu/admin_key.pub";

	upool = sp_priv_userpool_create();
	if (!upool)
		goto error;

	while ((c = getopt(argc, argv, "nhdDrsup:t:m:x:a:")) != -1) {
		switch (c) {
		case 'D':
			spc_chatty = 1;
			break;

		case 'd':
			debuglevel = 1;
			break;

		case 'p':
			port = strtol(optarg, &s, 10);
			if (*s != '\0')
				usage();
			break;

		case 't':
			tmppath = strdup(optarg);
			break;

		case 'r':
			retaintmpdir++;
			break;

		case 's':
			sameuser++;
			break;

		case 'm':
			msize = strtol(optarg, &s, 10);
			if (*s != '\0')
				usage();
			spc_msize = msize;
			break;

		case 'n':
			nokeys = 1;
			break;

		case 'a':
			afname = optarg;
			break;

		case 'u':
			init_unix_users(upool);
			break;

		case 'h':
		default:
			usage();
		}
	}

	adminkey = xauth_pubkey_create_from_file(afname);
	if (!adminkey) {
		adminkey = (Xkey *) ~0;
		sp_werror(NULL, 0);
	}

	xcpu_admin = getpwnam("xcpu-admin");
	if (xcpu_admin) {
		xcpu_uid = xcpu_admin->pw_uid;
		xcpu_gid = xcpu_admin->pw_gid;
	} else {
		xcpu_uid = 65530; 
		xcpu_gid = 65530;
	}
	adminuser = sp_priv_user_add(upool, "xcpu-admin", xcpu_uid, adminkey);
	if (!adminuser)
		goto error;
	user = adminuser;

	admingroup = sp_priv_group_add(upool, "xcpu-admin", xcpu_gid);
	if (!admingroup)
		goto error;

	sp_priv_group_adduser(admingroup, adminuser);
	sp_priv_user_setdfltgroup(adminuser, admingroup);
	sp_priv_user_add(upool, "nobody", 9999, NULL);

	fsinit();
	if (nsinit() < 0)
		goto error;
	srv = sp_socksrv_create_tcp(&port);
	if (!srv) 
		goto error;

	srv->dotu = 1;
	srv->reent = 0;
	srv->msize = msize;
	srv->auth = &xauth;
	srv->connopen = xconnopen;
	srv->connclose = xconnclose;
	srv->attach = spfile_attach;
	srv->clone = xclone;
	srv->walk = xwalk;
	srv->open = xopen;
	srv->create = xcreate;
	srv->read = xread;
	srv->write = xwrite;
	srv->clunk = xclunk;
	srv->remove = xremove;
	srv->stat = xstat;
	srv->wstat = xwstat;
	srv->flush = xflush;
	srv->fiddestroy = xfiddestroy;
	srv->upool = upool;
	srv->debuglevel = debuglevel;
	srv->treeaux = root;
	sp_srv_start(srv);

	if (!debuglevel) {
		close(0);
		open("/dev/null", O_RDONLY);
		close(1);
		open("/dev/null", O_WRONLY);
		close(2);
		open("/dev/null", O_WRONLY);

		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "cannot fork\n");
			return -1;
		}

		if (pid != 0) {
			/* parent */
			return 0;
		}

		/* child */
		setsid();
		chdir("/");
	}

#warning RACE CONDITION AND FAILURE ON SETUP ON MOUNT
	if (!fork()) {
		snprintf(mntopts, sizeof(mntopts), "msize=32792,port=%d", port);
		if (mount("127.0.0.1", "/mnt/xcpu", "9p", 0, mntopts) < 0) {
			perror("mount");
		}
		exit(0);
	}

	sact.sa_handler = SIG_IGN;
	sigemptyset(&sact.sa_mask);
	sact.sa_flags = 0;
	if (sigaction(SIGPIPE, &sact, NULL) < 0) {
		sp_uerror(errno);
		goto error;
	}

	sact.sa_handler = sigchld_handler;
	if (sigaction(SIGCHLD, &sact, NULL) < 0) {
		sp_uerror(errno);
		goto error;
	}
	sigchld_setup_pipe();

	sp_poll_loop();
	return 0;

error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "Error: %s\n", ename);
	return -1;
}

struct {
	char*	name;
	int	num;
} signals[] = {
	{"SIGHUP",      1} ,   /* Hangup (POSIX).  */
	{"SIGINT",      2} ,   /* Interrupt (ANSI).  */
	{"SIGQUIT",     3},   /* Quit (POSIX).  */
	{"SIGILL",      4},   /* Illegal instruction (ANSI).  */
	{"SIGTRAP",     5},   /* Trace trap (POSIX).  */
	{"SIGABRT",     6},   /* Abort (ANSI).  */
	{"SIGIOT",      6},   /* IOT trap (4.2 BSD).  */
	{"SIGBUS",      7},   /* BUS error (4.2 BSD).  */
	{"SIGFPE",      8},   /* Floating-point exception (ANSI).  */
	{"SIGKILL",     9},   /* Kill, unblockable (POSIX).  */
	{"SIGUSR1",     10},  /* User-defined signal 1 (POSIX).  */
	{"SIGSEGV",     11},  /* Segmentation violation (ANSI).  */
	{"SIGUSR2",     12},  /* User-defined signal 2 (POSIX).  */
	{"SIGPIPE",     13},  /* Broken pipe (POSIX).  */
	{"SIGALRM",     14},  /* Alarm clock (POSIX).  */
	{"SIGTERM",     15},  /* Termination (ANSI).  */
	{"SIGSTKFLT",   16},  /* Stack fault.  */
	{"SIGCLD",      17}, /* Same as SIGCHLD (System V).  */
	{"SIGCHLD",     17},  /* Child status has changed (POSIX).  */
	{"SIGCONT",     18},  /* Continue (POSIX).  */
	{"SIGSTOP",     19},  /* Stop, unblockable (POSIX).  */
	{"SIGTSTP",     20},  /* Keyboard stop (POSIX).  */
	{"SIGTTIN",     21},  /* Background read from tty (POSIX).  */
	{"SIGTTOU",     22},  /* Background write to tty (POSIX).  */
	{"SIGURG",      23},  /* Urgent condition on socket (4.2 BSD).  */
	{"SIGXCPU",     24},  /* CPU limit exceeded (4.2 BSD).  */
	{"SIGXFSZ",     25},  /* File size limit exceeded (4.2 BSD).  */
	{"SIGVTALRM",   26},  /* Virtual alarm clock (4.2 BSD).  */
	{"SIGPROF",     27},  /* Profiling alarm clock (4.2 BSD).  */
	{"SIGWINCH",    28},  /* Window size change (4.3 BSD, Sun).  */
	{"SIGPOLL",     29},   /* Pollable event occurred (System V).  */
	{"SIGIO",       29},  /* I/O now possible (4.2 BSD).  */
	{"SIGPWR",      30},  /* Power failure restart (System V).  */
	{"SIGSYS",      31},  /* Bad system call.  */
	{"SIGUNUSED",   31},
	{NULL, 0},
};


static int
signame2signo(char *sig)
{
	int i, n;
	char *e;

	n = strtol(sig, &e, 10);
	if (*e == '\0')
		return n;

	for(i = 0; signals[i].name != NULL; i++)
		if (strcmp(signals[i].name, sig) == 0)
			return signals[i].num;

	return -1;
}
