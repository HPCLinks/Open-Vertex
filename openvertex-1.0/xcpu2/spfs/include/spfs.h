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

#include <sys/types.h>
#include <stdint.h>

typedef uint8_t   u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef struct Spstr Spstr;
typedef struct Spqid Spqid;
typedef struct Spstat Spstat;
typedef struct Spwstat Spwstat;
typedef struct Spfcall Spfcall;
typedef struct Spfid Spfid;
typedef struct Spbuf Spbuf;
typedef struct Sptrans Sptrans;
typedef struct Spconn Spconn;
typedef struct Spreq Spreq;
typedef struct Spwthread Spwthread;
typedef struct Spauth Spauth;
typedef struct Spsrv Spsrv;
typedef struct Spuser Spuser;
typedef struct Spgroup Spgroup;
typedef struct Spuserpool Spuserpool;
typedef struct Spfile Spfile;
typedef struct Spfilefid Spfilefid;
typedef struct Spfileops Spfileops;
typedef struct Spdirops Spdirops;
typedef struct Spfd Spfd;

/* message types */
enum {
	Tfirst		= 100,
	Tversion	= 100,
	Rversion,
	Tauth		= 102,
	Rauth,
	Tattach		= 104,
	Rattach,
	Terror		= 106,
	Rerror,
	Tflush		= 108,
	Rflush,
	Twalk		= 110,
	Rwalk,
	Topen		= 112,
	Ropen,
	Tcreate		= 114,
	Rcreate,
	Tread		= 116,
	Rread,
	Twrite		= 118,
	Rwrite,
	Tclunk		= 120,
	Rclunk,
	Tremove		= 122,
	Rremove,
	Tstat		= 124,
	Rstat,
	Twstat		= 126,
	Rwstat,
	Rlast
};

/* modes */
enum {
	Oread		= 0x00,
	Owrite		= 0x01,
	Ordwr		= 0x02,
	Oexec		= 0x03,
	Oexcl		= 0x04,
	Otrunc		= 0x10,
	Orexec		= 0x20,
	Orclose		= 0x40,
	Oappend		= 0x80,

	Ouspecial	= 0x100,	/* internal use */
};

/* permissions */
enum {
	Dmdir		= 0x80000000,
	Dmappend	= 0x40000000,
	Dmexcl		= 0x20000000,
	Dmmount		= 0x10000000,
	Dmauth		= 0x08000000,
	Dmtmp		= 0x04000000,
	Dmsymlink	= 0x02000000,
	Dmlink		= 0x01000000,

	/* 9P2000.u extensions */
	Dmdevice	= 0x00800000,
	Dmnamedpipe	= 0x00200000,
	Dmsocket	= 0x00100000,
	Dmsetuid	= 0x00080000,
	Dmsetgid	= 0x00040000,
};

/* qid.types */
enum {
	Qtdir		= 0x80,
	Qtappend	= 0x40,
	Qtexcl		= 0x20,
	Qtmount		= 0x10,
	Qtauth		= 0x08,
	Qttmp		= 0x04,
	Qtsymlink	= 0x02,
	Qtlink		= 0x01,
	Qtfile		= 0x00,
};

#define NOTAG		(u16)(~0)
#define NOFID		(u32)(~0)
#define MAXWELEM	16
#define IOHDRSZ		24
#define FID_HTABLE_SIZE 64

struct Spstr {
	u16		len;
	char*		str;
};

struct Spqid {
	u8		type;
	u32		version;
	u64		path;
};

struct Spstat {
	u16 		size;
	u16 		type;
	u32 		dev;
	Spqid		qid;
	u32 		mode;
	u32 		atime;
	u32 		mtime;
	u64 		length;
	Spstr		name;
	Spstr		uid;
	Spstr		gid;
	Spstr		muid;

	/* 9P2000.u extensions */
	Spstr		extension;
	u32 		n_uid;
	u32 		n_gid;
	u32 		n_muid;
};

/* file metadata (stat) structure used to create Twstat message
   It is similar to Spstat, but the strings don't point to 
   the same memory block and should be freed separately
*/
struct Spwstat {
	u16 		size;
	u16 		type;
	u32 		dev;
	Spqid		qid;
	u32 		mode;
	u32 		atime;
	u32 		mtime;
	u64 		length;
	char*		name;
	char*		uid;
	char*		gid;
	char*		muid;
	char*		extension;	/* 9p2000.u extensions */
	u32 		n_uid;		/* 9p2000.u extensions */
	u32 		n_gid;		/* 9p2000.u extensions */
	u32 		n_muid;		/* 9p2000.u extensions */
};

struct Spfcall {
	u32		size;
	u8		type;
	u16		tag;
	u8*		pkt;

	u32		fid;
	u32		msize;			/* Tversion, Rversion */
	Spstr		version;		/* Tversion, Rversion */
	u32		afid;			/* Tauth, Tattach */
	Spstr		uname;			/* Tauth, Tattach */
	Spstr		aname;			/* Tauth, Tattach */
	Spqid		qid;			/* Rauth, Rattach, Ropen, Rcreate */
	Spstr		ename;			/* Rerror */
	u16		oldtag;			/* Tflush */
	u32		newfid;			/* Twalk */
	u16		nwname;			/* Twalk */
	Spstr		wnames[MAXWELEM];	/* Twalk */
	u16		nwqid;			/* Rwalk */
	Spqid		wqids[MAXWELEM];	/* Rwalk */
	u8		mode;			/* Topen, Tcreate */
	u32		iounit;			/* Ropen, Rcreate */
	Spstr		name;			/* Tcreate */
	u32		perm;			/* Tcreate */
	u64		offset;			/* Tread, Twrite */
	u32		count;			/* Tread, Rread, Twrite, Rwrite */
	u8*		data;			/* Rread, Twrite */
	Spstat		stat;			/* Rstat, Twstat */

	/* 9P2000.u extensions */
	u32		ecode;			/* Rerror */
	Spstr		extension;		/* Tcreate */
	u32		n_uname;		/* Tauth, Tattach */

	Spfcall*	next;
};

struct Spfid {
	Spconn*		conn;
	u32		fid;
	int		refcount;
	u16		omode;
	u8		type;
	u32		diroffset;
	Spuser*		user;
	void*		aux;

	Spfid*		next;	/* list of fids within a bucket */
};

struct Spconn {
	char*		address;	/* IP address!port */
	u32		msize;
	int		dotu;
	int		shutdown;
	int		fdin;
	int		fdout;
	Spfd*		spfdin;
	Spfd*		spfdout;
	Spsrv*		srv;
	Spfid**		fidpool;
	int		freercnum;
	Spfcall*	freerclist;

	Spfcall*	ifcall;
	int		ofcall_pos;
	Spfcall*	ofcall_first;
	Spfcall*	ofcall_last;

	Spconn*		next;	/* list of connections within a server */
};

struct Spreq {
	Spconn*		conn;
	u16		tag;
	Spfcall*	tcall;
	Spfcall*	rcall;
	int		cancelled;
	int		responded;
	Spreq*		flushreq;
	Spfid*		fid;

	Spreq*		next;	/* list of all outstanding requests */
	Spreq*		prev;	/* used for requests that are worked on */
};

struct Spauth {
	int		(*startauth)(Spfid *afid, char *aname, Spqid *aqid);
	int		(*checkauth)(Spfid *fid, Spfid *afid, char *aname);
	int		(*read)(Spfid *afid, u64 offset, u32 count, u8 *data);
	int		(*write)(Spfid *afid, u64 offset, u32 count, u8 *data);
	int		(*clunk)(Spfid *afid);
};

struct Spsrv {
	u32		msize;
	int		dotu;		/* 9P2000.u support flag */
	void*		srvaux;
	void*		treeaux;
	int		debuglevel;
	int		reent;
	Spauth*		auth;
	Spuserpool*	upool;

	void		(*start)(Spsrv *);
	void		(*shutdown)(Spsrv *);
	void		(*destroy)(Spsrv *);
	void		(*connopen)(Spconn *);
	void		(*connclose)(Spconn *);
	void		(*fiddestroy)(Spfid *);

	Spfcall*	(*version)(Spconn *conn, u32 msize, Spstr *version);
	Spfcall*	(*attach)(Spfid *fid, Spfid *afid, Spstr *uname, 
				Spstr *aname, u32 n_uname);
	Spfcall*	(*flush)(Spreq *req);
	int		(*clone)(Spfid *fid, Spfid *newfid);
	int		(*walk)(Spfid *fid, Spstr *wname, Spqid *wqid);
	Spfcall*	(*open)(Spfid *fid, u8 mode);
	Spfcall*	(*create)(Spfid *fid, Spstr* name, u32 perm, u8 mode, 
				Spstr* extension);
	Spfcall*	(*read)(Spfid *fid, u64 offset, u32 count, Spreq *req);
	Spfcall*	(*write)(Spfid *fid, u64 offset, u32 count, u8 *data, 
				Spreq *req);
	Spfcall*	(*clunk)(Spfid *fid);
	Spfcall*	(*remove)(Spfid *fid);
	Spfcall*	(*stat)(Spfid *fid);
	Spfcall*	(*wstat)(Spfid *fid, Spstat *stat);

	/* implementation specific */
	int		nreqs;		/* number of simultaneously processed
					   (reentrant) requests */
	Spconn*		conns;
	Spreq*		reqs_first;
	Spreq*		reqs_last;
	Spreq*		workreqs;
	int		enomem;		/* if set, returning Enomem Rerror */
	Spfcall*	rcenomem;	/* preallocated to send if no memory */
	Spfcall*	rcenomemu;	/* same for .u connections */
};

struct Spuser {
	int			refcount;
	Spuserpool*	upool;
	char*		uname;
	uid_t		uid;
	Spgroup*	dfltgroup;
	int		ngroups;
	Spgroup**	groups;
	void*		aux;

	Spuser*		next;
};

struct Spgroup {
	int		refcount;
	Spuserpool*	upool;
	char*		gname;
	gid_t		gid;
	void*		aux;

	Spgroup*	next;
};

struct Spuserpool {
	void*		aux;
	Spuser*		(*uname2user)(Spuserpool *, char *uname);
	Spuser*		(*uid2user)(Spuserpool *, u32 uid);
	Spgroup*	(*gname2group)(Spuserpool *, char *gname);
	Spgroup*	(*gid2group)(Spuserpool *, u32 gid);
	int		(*ismember)(Spuserpool *, Spuser *u, Spgroup *g);
	void		(*udestroy)(Spuserpool *, Spuser *u);
	void		(*gdestroy)(Spuserpool *, Spgroup *g);
};

struct Spfile {
	int		refcount;
	Spfile*		parent;
	Spqid		qid;
	u32		mode;
	u32		atime;
	u32		mtime;
	u64		length;
	char*		name;
	Spuser*		uid;
	Spgroup*	gid;
	Spuser*		muid;
	char*		extension;
	int		excl;
	void*		ops;
	void*		aux;

	/* not used -- provided for user's convenience */
	Spfile*		next;
	Spfile*		prev;
	Spfile*		dirfirst;
	Spfile*		dirlast;
};

struct Spfileops {
//	Spuserpool*	upool;
	void		(*ref)(Spfile *, Spfilefid *);
	void		(*unref)(Spfile *, Spfilefid *);
	int		(*read)(Spfilefid* file, u64 offset, u32 count, 
				u8 *data, Spreq *req);
	int		(*write)(Spfilefid* file, u64 offset, u32 count, 
				u8 *data, Spreq *req);
	int		(*wstat)(Spfile*, Spstat*);
	void		(*destroy)(Spfile*);
	int		(*openfid)(Spfilefid *);
	void		(*closefid)(Spfilefid *);
};

struct Spdirops {
//	Spuserpool*	upool;
	void		(*ref)(Spfile *, Spfilefid *);
	void		(*unref)(Spfile *, Spfilefid *);
	Spfile*		(*create)(Spfile *dir, char *name, u32 perm, 
				Spuser *uid, Spgroup *gid, char *extension);
	Spfile*		(*first)(Spfile *dir);
	Spfile*		(*next)(Spfile *dir, Spfile *prevchild);
	int		(*wstat)(Spfile*, Spstat*);
	int		(*remove)(Spfile *dir, Spfile *file);
	void		(*destroy)(Spfile*);
	Spfilefid*	(*allocfid)(Spfile *);
	void		(*destroyfid)(Spfilefid *);
};

struct Spfilefid {
	Spfid*		fid;
	Spfile*		file;
	int		omode;
	void*		aux;
	u64		diroffset;
	Spfile*		dirent;
};

extern char *Eunknownfid;
extern char *Enomem;
extern char *Enoauth;
extern char *Enotimpl;
extern char *Einuse;
extern char *Ebadusefid;
extern char *Enotdir;
extern char *Etoomanywnames;
extern char *Eperm;
extern char *Etoolarge;
extern char *Ebadoffset;
extern char *Edirchange;
extern char *Enotfound;
extern char *Eopen;
extern char *Eexist;
extern char *Enotempty;
extern char *Eunknownuser;
extern Spuserpool *sp_unix_users;

Spfd *spfd_add(int fd, void (*notify)(Spfd *, void *), void *aux);
void spfd_remove(Spfd *spfd);
void spfd_remove_all(void);
int spfd_can_read(Spfd *spfd);
int spfd_can_write(Spfd *spfd);
int spfd_has_error(Spfd *spfd);
int spfd_read(Spfd *spfd, void *buf, int buflen);
int spfd_write(Spfd *spfd, void *buf, int buflen);
void sp_poll_once();
void sp_poll_loop(void);
void sp_poll_stop(void);
int sp_poll_looping(void);

Spsrv *sp_srv_create(void);
void sp_srv_start(Spsrv *srv);
int sp_srv_add_conn(Spsrv *srv, Spconn *conn);
void sp_srv_remove_conn(Spsrv *srv, Spconn *conn);
void sp_respond(Spreq *req, Spfcall *rcall);
Spfcall *sp_srv_get_enomem(Spsrv *srv, int dotu);

Spconn *sp_conn_create(Spsrv *srv, char *address, int fdin, int fdout);
void sp_conn_reset(Spconn *srv, u32 msize, int dotu);
void sp_conn_respond(Spconn *conn, Spfcall *tc, Spfcall *rc);

Spfid **sp_fidpool_create(void);
void sp_fidpool_destroy(Spfid **);
Spfid *sp_fid_find(Spconn *, u32);
Spfid *sp_fid_create(Spconn *, u32, void *);
int sp_fid_destroy(Spfid *);
void sp_fid_incref(Spfid *);
void sp_fid_decref(Spfid *);

int sp_deserialize(Spfcall*, u8*, int);
int sp_serialize_stat(Spwstat *wstat, u8* buf, int buflen, int dotu);
int sp_deserialize_stat(Spstat *stat, u8* buf, int buflen, int dotu);

char *sp_strdup(Spstr *str);
int sp_strcmp(Spstr *str, char *cs);
int sp_strncmp(Spstr *str, char *cs, int len);

void sp_set_tag(Spfcall *, u16);
Spfcall *sp_create_tversion(u32 msize, char *version);
Spfcall *sp_create_rversion(u32 msize, char *version);
Spfcall *sp_create_tauth(u32 fid, char *uname, char *aname, u32 n_uid, int dotu);
Spfcall *sp_create_rauth(Spqid *aqid);
Spfcall *sp_create_rerror(char *ename, int ecode, int dotu);
Spfcall *sp_create_rerror1(Spstr *ename, int ecode, int dotu);
Spfcall *sp_create_tflush(u16 oldtag);
Spfcall *sp_create_rflush(void);
Spfcall *sp_create_tattach(u32 fid, u32 afid, char *uname, char *aname, u32 n_uid, int dotu);
Spfcall *sp_create_rattach(Spqid *qid);
Spfcall *sp_create_twalk(u32 fid, u32 newfid, u16 nwname, char **wnames);
Spfcall *sp_create_rwalk(int nwqid, Spqid *wqids);
Spfcall *sp_create_topen(u32 fid, u8 mode);
Spfcall *sp_create_ropen(Spqid *qid, u32 iounit);
Spfcall *sp_create_tcreate(u32 fid, char *name, u32 perm, u8 mode, char *extension, int dotu);
Spfcall *sp_create_rcreate(Spqid *qid, u32 iounit);
Spfcall *sp_create_tread(u32 fid, u64 offset, u32 count);
Spfcall *sp_create_rread(u32 count, u8* data);
Spfcall *sp_create_twrite(u32 fid, u64 offset, u32 count, u8 *data);
Spfcall *sp_create_rwrite(u32 count);
Spfcall *sp_create_tclunk(u32 fid);
Spfcall *sp_create_rclunk(void);
Spfcall *sp_create_tremove(u32 fid);
Spfcall *sp_create_rremove(void);
Spfcall *sp_create_tstat(u32 fid);
Spfcall *sp_create_rstat(Spwstat *stat, int dotu);
Spfcall *sp_create_twstat(u32 fid, Spwstat *wstat, int dotu);
Spfcall *sp_create_rwstat(void);
Spfcall *sp_alloc_rread(u32);
void sp_set_rread_count(Spfcall *, u32);

void sp_user_incref(Spuser *);
void sp_user_decref(Spuser *);
void sp_group_incref(Spgroup *);
void sp_group_decref(Spgroup *);
int sp_change_user(Spuser *u);
Spuser* sp_current_user(void);

Spuserpool *sp_priv_userpool_create();
Spuser *sp_priv_user_add(Spuserpool *up, char *uname, u32 uid, void *aux);
void sp_priv_user_del(Spuser *u);
Spuser *sp_priv_user_list(Spuserpool *up);
int sp_priv_user_setdfltgroup(Spuser *u, Spgroup *g);
Spgroup *sp_priv_group_add(Spuserpool *up, char *gname, u32 gid);
void sp_priv_group_del(Spgroup *g);
Spgroup *sp_priv_group_list(Spuserpool *up);
int sp_priv_group_adduser(Spgroup *g, Spuser *u);
int sp_priv_group_deluser(Spgroup *g, Spuser *u);

Spsrv *sp_socksrv_create_tcp(int*);
Spsrv *sp_pipesrv_create();
int sp_pipesrv_mount(Spsrv *srv, char *mntpt, char *user, int mntflags, char *opts);

void sp_werror(char *ename, int ecode, ...);
void sp_rerror(char **ename, int *ecode);
void sp_uerror(int ecode);
void sp_suerror(char *s, int ecode);
int sp_haserror(void);

Spfile* spfile_alloc(Spfile *parent, char *name, u32 mode, u64 qpath, 
	void *ops, void *aux);
void spfile_incref(Spfile *);
int spfile_decref(Spfile *);
Spfile *spfile_find(Spfile *, char *);
int spfile_checkperm(Spfile *file, Spuser *user, int perm);
void spfile_init_srv(Spsrv *, Spfile *);

void spfile_fiddestroy(Spfid *fid);
Spfcall *spfile_attach(Spfid *fid, Spfid *afid, Spstr *uname, Spstr *aname, u32 n_uname);
int spfile_clone(Spfid *fid, Spfid *newfid);
int spfile_walk(Spfid *fid, Spstr *wname, Spqid *wqid);
Spfcall *spfile_open(Spfid *fid, u8 mode);
Spfcall *spfile_create(Spfid *fid, Spstr* name, u32 perm, u8 mode, Spstr* extension);
Spfcall *spfile_read(Spfid *fid, u64 offset, u32 count, Spreq *req);
Spfcall *spfile_write(Spfid *fid, u64 offset, u32 count, u8 *data, Spreq *req);
Spfcall *spfile_clunk(Spfid *fid);
Spfcall *spfile_remove(Spfid *fid);
Spfcall *spfile_stat(Spfid *fid);
Spfcall *spfile_wstat(Spfid *fid, Spstat *stat);

int sp_printfcall(FILE *f, Spfcall *fc, int dotu);
void *sp_malloc(int);
