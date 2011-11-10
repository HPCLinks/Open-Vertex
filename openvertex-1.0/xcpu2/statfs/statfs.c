#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <signal.h>
#include <regex.h>
#include <math.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <ctype.h>
#include <pwd.h>
#include <netdb.h>

#include "npfs.h"
#include "npclient.h"
#include "strutil.h"
#include "xcpu.h"
#include "libxauth.h"

typedef struct Node Node;
struct Node {
	char*		name;
	char*		addr;
	struct          addrinfo *addrlist;
	char		arch[64];
	char		status[64];
        int             numjobs; /* number of jobs running on this node */
	time_t		tstamp;	/* last time we read the state file */
	Npcfsys*	fs;
	Npcfid*		fid;	/* state fid */
	char		ename[64];
	int		ecode;
	pthread_t	proc;
	Node*		next;
	pthread_mutex_t lock;
};

enum {
	Qroot = 1,
	Qstate,
};

extern int npc_chatty;
static Npfile *dir_first(Npfile *dir);
static Npfile *dir_next(Npfile *dir, Npfile *prevchild);
static Npfile *create_file(Npfile *parent, char *name, u32 mode,
	u64 qpath, void *ops, Npuser *usr, void *aux);
static int state_read(Npfilefid *fid, u64 offset, u32 count, u8 *data,
	Npreq *req);
static void nodedisconnect(Node *nd);
static int nodeauth(Npcfid *afid, Npuser *user, void *aux);
static void nodestatus(Node *nd, char *status);

Npdirops root_ops = {
	.first = dir_first,
	.next = dir_next,
};

Npfileops state_ops = {
	.read = state_read,
};

Npsrv *srv;
Npfile *root;
int port = STAT_PORT;
int debuglevel;

//static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int timeout = 5;
Node *nodes;
Npuserpool *up;
Npuser *user;
Npuser *adminuser;	/* the user connecting to xcpufs */
Xkey *adminkey;		/* the key to connect to xcpufs */

static void 
usage(char *name) {
	fprintf(stderr, "usage: %s [-D] [-d debuglevel] [-p port] <-c configfile> <-a admin_key>\n", name);
	exit(1);
}

static Node *
nodecreate(char *name, char *addr)
{
	Node *nd;

	nd = np_malloc(sizeof(*nd));
	if (!nd)
		return NULL;

	/* there are a host of unchecked errors here. 
	 * Allocation failures really ought to just be a panic methinks. 
	 */
	nd->name = strdup(name);
	nd->addr = strdup(addr);
	nd->addrlist = npc_netaddr(nd->addr, XCPU_PORT);
	if (!nd->addrlist) {
		/* Make sure stderr is open ... we're going to 
		 * die but let's return an error, not exit!
		 */
		fprintf(stderr, "%s is not resolvable to a host address\n", addr);
		/* we could free here but why bother? We're going to die */
		return NULL;
	}
	snprintf(nd->arch, sizeof(nd->arch), "unknown (not read yet)");
	nd->tstamp = 0;
	nd->fs = NULL;
	nd->fid = NULL;
	nd->next = NULL;
	nd->numjobs = 0;
	snprintf(nd->status, sizeof(nd->status), "down(initializing)");
	pthread_mutex_init(&nd->lock, NULL);
	return nd;
}

static void
nodedestroy(Node *nd)
{
	nodedisconnect(nd);
	free(nd->name);
	nd->name = NULL;
	free(nd->addr);
	nd->addr = NULL;
	freeaddrinfo(nd->addrlist);
	free(nd);
}

static int
nodeconnect(Node *nd)
{
	int n;
	Npcfid *fid;

	nodedisconnect(nd);
	//	fprintf(stdout, "%s: mounting\n", nd->name);
	nd->fs = npc_netmount(nd->addrlist, adminuser, XCPU_PORT, nodeauth, adminkey);
	if (!nd->fs) 
	  return -1;
	
	fid = npc_open(nd->fs, "arch", Oread);
	if (!fid)
		return -1;

	n = npc_read(fid, (u8 *) nd->arch, sizeof(nd->arch), 0);
	if (n < 0) {
		npc_close(fid);
		return -1;
	}
	nd->arch[n] = '\0';
	npc_close(fid);

	nd->fid = npc_open(nd->fs, "state", Oread);
	if (!nd->fid)
		return -1;

	return 0;
}

static void
nodedisconnect(Node *nd)
{
	if (nd->fid) {
		npc_close(nd->fid);
		nd->fid = NULL;
	}

	if (nd->fs) {
		npc_umount(nd->fs);
		nd->fs = NULL;
	}

	nodestatus(nd, "down(disconnected)");
}

static void
nodeerror(Node *nd)
{
	int ecode;
	char *ename;

	np_rerror(&ename, &ecode);
	pthread_mutex_lock(&nd->lock);
	strncpy(nd->ename, ename, sizeof(nd->ename));
	nd->ecode = ecode;
	pthread_mutex_unlock(&nd->lock);
	np_werror(NULL, 0);
}

static void
nodereseterror(Node *nd)
{
	pthread_mutex_lock(&nd->lock);
	if (nd->ecode) {
		nd->ecode = 0;
		*nd->ename = '\0';
	}
	pthread_mutex_unlock(&nd->lock);
}

static int
nodeauth(Npcfid *afid, Npuser *user, void *aux)
{
	int n;
	char buf[4096], sig[4096];
	Xkey *key;

	key = aux;
	n = npc_read(afid, (u8 *) buf, sizeof(buf), 0);
	if (n < 0)
		return -1;
	else if (n == 0) {
		np_werror("authentication failed", EIO);
		return -1;
	}

	n = xauth_sign((u8 *) buf, n, (u8 *) sig, sizeof(sig), key);
	if (n < 0)
		return -1;

	n = npc_write(afid, (u8 *) sig, n, 0);
	if (n < 0)
		return -1;

	return 0;
}

static void
nodestatus(Node *nd, char *status)
{
	pthread_mutex_lock(&nd->lock);
	strncpy(nd->status, status, sizeof(nd->status));
	nd->tstamp = time(NULL);
	if (!strcmp(nd->status, "down")) 
		nd->numjobs = 0;
	pthread_mutex_unlock(&nd->lock);
}

static void
nodenumjobs(Node *nd) 
{
  int n, i, counter;
  Npwstat *stat;
  char *end;
  Npcfid* dirid;
	
  dirid = npc_open(nd->fs, "/", Oread);
  pthread_mutex_lock(&nd->lock);
  
  if (!dirid)
	  nd->numjobs = 0;  //If "/" can't be opened, set numjobs to 0
  else {
	  counter = 0;
	  if ((n = npc_dirread(dirid, &stat)) > 0) {     //Read each file in Node's
		  for (i = 0; i < n; i++) {              //xcpufs root dir and if
			  strtol(stat[i].name, &end, 10);//a file is a number, then
			                                 //it represents a running job
			  if (stat[i].name != '\0' && *end == '\0')
				  counter++;
		  }
		  free(stat);
	  }
	  
	  if ( n < 0)
		  nd->numjobs = 0;  //If there was an error reading, set numjobs to 0
	  
	  else {
		  if (counter != nd->numjobs)
			  nd->numjobs = counter;
	  }
  }
  
  pthread_mutex_unlock(&nd->lock);
  npc_close(dirid);
}

static void *
nodeproc(void *a)
{
	int n;
	char buf[512];
	Node *nd;

	nd = a;
	while (1) {

		if (!nd->fs || nd->ecode) {
			nodestatus(nd, "down(connect_failed)");
			if (nodeconnect(nd) < 0) {
				nodeerror(nd);
				goto sleep;
			}
		}

		n = npc_read(nd->fid, (u8 *) buf, sizeof(buf), 0);
		if (n < 0) {
			nodestatus(nd, "down(read_failed)");
			nodeerror(nd);
			continue;
		}

		buf[n] = '\0';
		if (n == 0) {
		  	nodereseterror(nd);
			strncpy(buf, "up", sizeof(buf));
		}

		nodestatus(nd, buf);
		nodenumjobs(nd);
sleep:
		sleep(timeout);
	}
}

static int
configread(char *path)
{
	int n;
	int errorcount = 0;
	char buf[1024], *p, *s;
	FILE *f;
	Node *nd, **lnd;

	f = fopen(path, "r");
	if (!f) {
		np_uerror(errno);
		return -1;
	}

	lnd = &nodes;

	/* there are few things worse than a program that feeds you
	 * config file errors one line at a time. So, if you get an
	 * error, track the fact, but keep trying to parse, so
	 * they can see *ALL* the errors
	 */

	while (fgets(buf, sizeof(buf), f) != NULL) {
		n = strlen(buf);
		if (buf[n - 1] == '\n') {
			n--;
			buf[n] = '\0';
		}

		/* get rid of the comments */
		p = strchr(buf, '#');
		if (p)
			*p = '\0';

		/* get rid of the spaces in the front */
		for(s = buf; isspace(*s); s++)
			;

		if (*s == '\0')
			continue;

		p = strchr(buf, '=');
		if (!p) {
			np_werror("invalid format: %s", EIO, buf);
			errorcount++;
			continue;
		}
		*p = '\0';
		p++;

		/* get rid of the spaces at the end */
		n = strlen(p);
		for(n = strlen(p) - 1; isspace(p[n]); n--)
			;
		p[n+1] = '\0';

		nd = nodecreate(s, p);
		if (!nd){
			errorcount++;
			continue;
		}

		*lnd = nd;
		lnd = &nd->next;
	}

	fclose(f);
	return -errorcount;

}

static Npfile*
dir_first(Npfile *dir)
{
	npfile_incref(dir->dirfirst);
	return dir->dirfirst;
}

static Npfile*
dir_next(Npfile *dir, Npfile *prevchild)
{
	npfile_incref(prevchild->next);
	return prevchild->next;
}

static Npfile *
create_file(Npfile *parent, char *name, u32 mode, u64 qpath, void *ops, 
	Npuser *usr, void *aux)
{
	Npfile *ret;

	ret = npfile_alloc(parent, name, mode, qpath, ops, aux);
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
	ret->gid = usr->dfltgroup;
	npfile_incref(ret);
	return ret;
}

static int
state_read(Npfilefid *fid, u64 offset, u32 count, u8 *data, Npreq *req)
{
	int ret, boff, blen;
	Node *nd;
	char buf[8192];

	boff = 0;
	ret = 0;
	for(nd = nodes; nd != NULL; nd = nd->next) {
		snprintf(buf, sizeof(buf), "%s\t%s\t%s\t%s\t%d\n", nd->name,
			 nd->addr, nd->arch, nd->status, nd->numjobs);
		blen = strlen(buf);
		ret += cutbuf(data, offset, count, buf, boff, blen);
		boff += blen;
	}
	
	return ret;
}

static void
fsinit(void)    
{      
	Npfile *file;

	root = npfile_alloc(NULL, "", 0555 | Dmdir, Qroot, &root_ops, NULL);
	root->parent = root;
	npfile_incref(root);
	root->atime = root->mtime = time(NULL);
	root->uid = root->muid = user;
	root->gid = user->dfltgroup;

	file = create_file(root, "state", 0444, Qstate, &state_ops, NULL, NULL);	
	file->length = 32;
}

int
main(int argc, char **argv)
{
	pid_t pid;
	int c, ecode, nwthreads, tstamp;
	uid_t uid;
	char *s, *ename, *cfg, *afname;
	Npuserpool *upool;
	struct passwd *xcpu_admin;
	Node *nd;
	pthread_attr_t attr;
	size_t stacksize;

	nwthreads = 8;
	afname = "/etc/xcpu/admin_key";
	cfg = "/etc/xcpu/statfs.conf";
	upool = np_priv_userpool_create();
	if (!upool)
		goto error;

	while ((c = getopt(argc, argv, "Dda:p:c:")) != -1) {
		switch (c) {
		case 'a':
			afname = optarg;
			break;
		case 'p':
			port = strtol(optarg, &s, 10);
			if(*s != '\0')
				usage(argv[0]);
			break;
		case 'D':
			npc_chatty = 1;
			break;
		case 'd':
			debuglevel = 1;
			break;
		case 'c':
			cfg = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	/* it's a good idea to read the config file and get error messages
	 * *before* you close 1 and 2 :-)
	 */

	if (configread(cfg) < 0)
		goto error;

	if(!debuglevel && !npc_chatty) {
		switch(pid = fork()) {;
		case -1:
			perror("cannot fork");
			exit(1);
		case 0:
			/* child */
			close(0);
			open("/dev/null", O_RDONLY);
			close(1);
			open("/dev/null", O_WRONLY);
			close(2);
			open("/dev/null", O_WRONLY);

			setsid();
			chdir("/");
			break;
		default:
			/* parent */
			exit(0);
		}
	}

	upool = np_priv_userpool_create();
	adminkey = xauth_privkey_create(afname);
	if (!adminkey)
		goto error;

	xcpu_admin = getpwnam("xcpu-admin");
	if (xcpu_admin)
		uid = xcpu_admin->pw_uid;
	else
		uid = 65530;

	adminuser = np_priv_user_add(upool, "xcpu-admin", uid, adminkey);
	if (!adminuser)
		goto error;

        /* make a reasonable default stack size. Most Linux default to 2M! */
	stacksize = 64 * 1024;
	if (pthread_attr_init(&attr)) {
		np_uerror(errno);
		goto error;
	}

	if (pthread_attr_setstacksize(&attr, stacksize)) {
		np_uerror(errno);
		goto error;
	}

	for(nd = nodes; nd != NULL; nd = nd->next)
		pthread_create(&nd->proc, NULL, nodeproc, nd);

	user = np_unix_users->uid2user(np_unix_users, geteuid());
	fsinit();
	srv = np_socksrv_create_tcp(nwthreads, &port);
	if (!srv)
		goto error;

	npfile_init_srv(srv, root);
	srv->debuglevel = debuglevel;
	np_srv_start(srv);
	while (1) {
		sleep(timeout);
		
		/*if we didn't get a response from a node for longer
		  than 2*timeout, assume it is down */
		tstamp = time(NULL);
		
		for(nd = nodes; nd != NULL; nd = nd->next) {
			pthread_mutex_lock(&nd->lock);
			if (nd->tstamp+2*timeout < tstamp && !nd->ecode) {
				nd->ecode = -1;
				strncpy(nd->status, "down(no_contact)", sizeof(nd->status));
			}
			pthread_mutex_unlock(&nd->lock);
		}
		
	}

	return 0;

error:
	np_rerror(&ename, &ecode);
	fprintf(stderr, "%s\n", ename);
	return -1;
}

