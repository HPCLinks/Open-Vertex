typedef struct Xsession Xsession;
typedef struct Xfilepipe Xfilepipe;
typedef struct Xfilebuf Xfilebuf;
typedef struct Xpipereq Xpipereq;
typedef struct Xwaitreq Xwaitreq;
typedef struct Fsfid Fsfid;
typedef struct Rxfile Rxfile;
typedef struct Rxcopy Rxcopy;
typedef struct Tspawn Tspawn;
typedef struct Xuser Xuser;

#define QBITS		24
#define QMASK		((1<<QBITS) - 1)
#define QPATH(id)	((id + 1) << 24)

enum {
	Read,
	Write,
};

struct Xfilepipe {
	int		err;
	int		lfd;
	int		rfd;
	int		direction;
	Spfd*		lspfd;
	char*		buf;
	int		buflen;
	int		bufsize;
	Xpipereq*	reqs;
};

struct Xpipereq {
	int		cancelled;
	Spfid*		fid;
	Xfilepipe*	pip;
	Spreq*		req;
	Spfcall*	rc;	/* for Tread */
	Xpipereq*	next;
};

struct Xwaitreq {
	Spreq*		req;
	Xwaitreq*	next;
};

struct Xfilebuf {
	int 		size;
	char*		buf;
};

enum {
	/* root level files */
	Qroot = 1,
	Qclone,
	Quname,
	Qarch,
	Qenv,
	Qprocs,
	Qstate,
	Qspu,
	Qpkey,
	Qctl,
	Qpwent,
	Qgrent,
	Qglobns,

	/* session level files */
	Qsctl = 1,
	Qexec,
	Qargv,
	Qsenv,
	Qstdin,
	Qstdout,
	Qstderr,
	Qstdio,
	Qwait,
	Qid,
	Qfs,
	Qns,
};

/* states */
enum {
	Initializing,
	Running,
	Finished,
	Wiped = 16,
};

/* modes */
enum {
	Normal,
	Persistent,
};

struct Xsession {
	int		refcount;
	int		sid;
	int		state;
	int		mode;
	Xfilebuf	argv;
	Xfilebuf	env;
	Xfilebuf	ns;

	char*		gid;
	int		lid;

	char*		ctl;
	Spreq*		ctlreq;
	int		ctlpos;

	Xfilepipe*	stin;
	Xfilepipe*	stout;
	Xfilepipe*	sterr;

	char*		stinfname;
	char*		stoutfname;
	char*		sterrfname;
	char*		dirpath;
	char*		execpath;
	int		pid;
	char*		exitstatus;

	Spfile*		sroot;
	Spfile*		fsdir;
	Xwaitreq*	waitreqs;
	Xsession*	next;

	/* upstream session */
	Spcfsys*	upfs;
	char*		uprefix;
};

struct Fsfid {
	char*		path;
	int		omode;
	int		fd;
	DIR*		dir;
	int		diroffset;
	char*		direntname;
	struct stat	stat;
	Xsession*	xs;
};

struct Tspawn;
struct Rxcopy;

struct Rxfile {
	Spcfsys*	fs;
	char*		name;
	u32		perm;
	int		create;	/* if 1, create, otherwise open witn Otrunc */

	char*		path;	/* if not NULL the file's content is read from the fs */
	char*		buf;	/* if path NULL, the content of the file, freed when Rxfile is destroyed */
	int		bufsize;
	int		buflen;
	Rxfile*		next;

	/* required for the copying */
	int		fd;
	Spcfid*		fid;
	Spcfd*		spcfd;
	int		pos;
};

struct Xuser {
	char*		uname;
	uid_t		uid;
	Xkey*		pubkey;

	Xuser*		next;
};

extern Xsession *sessions;
extern Spuser *adminuser;
extern Xkey *adminkey;
extern Xkey *xcpukey;

/* pipe.c */
Xfilepipe *pip_create(int direction);
void pip_destroy(Xfilepipe *p);
int pip_addreq(Xfilepipe* p, Spreq *req);
int pip_flushreq(Xfilepipe *p, Spreq *req);
void pip_close_remote(Xfilepipe *p);
void pip_close_local(Xfilepipe *p);

/* ufs.c */
int ufs_clone(Spfid *fid, Spfid *newfid);
int ufs_walk(Spfid *fid, Spstr *wname, Spqid *wqid);
Spfcall *ufs_open(Spfid *fid, u8 mode);
Spfcall *ufs_create(Spfid *fid, Spstr *name, u32 perm, u8 mode, Spstr *extension);
Spfcall *ufs_read(Spfid *fid, u64 offset, u32 count, Spreq *);
Spfcall *ufs_write(Spfid *fid, u64 offset, u32 count, u8 *data, Spreq *);
Spfcall *ufs_clunk(Spfid *fid);
Spfcall *ufs_remove(Spfid *fid);
Spfcall *ufs_stat(Spfid *fid);
Spfcall *ufs_wstat(Spfid *fid, Spstat *stat);
void ufs_fiddestroy(Spfid *fid);
void ufs_attach(Spfid *nfid, Xsession *xs, Spqid *qid);

int session_incref(Xsession *xs);
void session_decref(Xsession *xs);
void sctl_execute_commands(Xsession *xs, Spuser *user);

/* tspawn.c */
int tspawn(Xsession *xs, int maxsessions, char *dest, Spuser *user);

/* xauth.c */
int xauth_init(char *xcpukey_fname, char *adminkey_fname);
int xauth_startauth(Spfid *afid, char *aname, Spqid *aqid);
int xauth_checkauth(Spfid *fid, Spfid *afid, char *aname);
int xauth_read(Spfid *fid, u64 offset, u32 count, u8 *data);
int xauth_write(Spfid *fid, u64 offset, u32 count, u8 *data);
int xauth_clunk(Spfid *fid);
int ukey_add(Spuserpool *up, char *uname, u32 uid, char *dfltgname, 
	char *key, int keylen);
int ukey_del(Spuserpool *up, char *uname);
int ukey_flush(Spuserpool *up);
int ukey_add_group(Spuserpool *up, char *uname, char *gname);
int ukey_del_group(Spuserpool *up, char *uname, char *gname);
int pkey_gen(Spuser *user, char *buf, int buflen);
int group_add(Spuserpool *up, char *groupname, u32 gid);
int group_del(Spuserpool *up, char *groupname);
int group_flush(Spuserpool *up);


/* proc-*.c */
char *getprocs(void);

/* file.c */
Rxfile *rxfile_create_from_file(Spcfsys *fs, char *name, char *path);
Rxfile *rxfile_create_from_buf(Spcfsys *fs, char *name, char *buf, int buflen);
void rxfile_destroy(Rxfile *f);
void rxfile_destroy_all(Rxfile *f);
Rxcopy *rxfile_copy_start(Rxfile *files, void (*cb)(void *), void *);
int rxfile_copy_finish(Rxcopy *c);


