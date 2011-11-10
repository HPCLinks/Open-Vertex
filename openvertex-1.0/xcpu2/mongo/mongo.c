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

#include "spfs.h"
#include "strutil.h"
#include "xcpu.h"

#include "mongo.h"

enum {
	WriteSize = 1024,
};

Spdirops root_ops = {
	.first = dir_first,
	.next = dir_next,
};

Spfileops ctl_ops = {
	.read = ctl_read,
	.write = ctl_write,
	.wstat = ctl_wstat,	/* to handle linux' lunacy */
};

Spfileops push_ops = {
	.read = push_read,
};

Spfileops pull_ops = {
	.read = pull_read,
};

Spuser *user;
Spsrv 	*srv;
Spfile 	*root;

char ctl[WriteSize+1];	/* silly buffer for holding writes */

int	port = 20005;
int	nodetach;

static void 
usage(char *name) {
	fprintf(stderr, "usage: %s [-n] [-p port]\n", name);
	exit(1);
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
	ret->gid = usr->dfltgroup;
	spfile_incref(ret);
	return ret;
}

static void
fsinit(void)	
{		   
	root = spfile_alloc(NULL, "", 0755 | Dmdir, Qroot, &root_ops, NULL);
	root->parent = root;
	spfile_incref(root);
	root->atime = root->mtime = time(NULL);
	root->uid = root->muid = user;
	root->gid = user->dfltgroup;
			
	create_file(root, "ctl", 0666, Qctl, &ctl_ops, NULL, NULL);
	create_file(root, "push", 0444, Qpush, &push_ops, NULL, NULL);
	create_file(root, "pull", 0444, Qpull, &pull_ops, NULL, NULL);
}


int
main(int argc, char **argv)
{
	int c, ecode, debuglevel;
	char *s, *ename;

	while ((c = getopt(argc, argv, "nD:p:")) != -1) {
		switch (c) {
		case 'D':
			debuglevel = strtol(optarg, &s, 10);
			if(*s != '\0')
				usage(argv[0]);
			break;
		case 'n':
			nodetach++;
			break;
		case 'p':
			port = strtol(optarg, &s, 10);
			if(*s != '\0')
				usage(argv[0]);
			break;
		default:
			usage(argv[0]);
		}
	}

	if (optind != argc)
		usage(argv[0]);

	memcpy(ctl, "thank you for reading ctl!\n", 30);

	user = sp_uid2user(getuid());
	if (!user) {
		fprintf(stderr, "user not found\n");
		exit(1);
	}

	fsinit();
	srv = sp_socksrv_create_tcp(&port);
	if (!srv)
		goto error;

	if(nodetach == 0)
		daemon(0, 0);

	spfile_init_srv(srv, root);
	srv->debuglevel = debuglevel;
	srv->dotu = 1;
	sp_srv_start(srv);
	sp_poll_loop();

error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "%s\n", ename);
	return -1;

}

static int
ctl_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	return cutstr(data, offset, count, ctl, 0);
}

static int
ctl_write(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	int left = WriteSize - offset;

	if(offset >= WriteSize)
		return 0;

	if(count < left)
		left = count;

	memcpy(ctl+offset, data, left);
	ctl[offset+left+1] = '\0';

	return left;
}

static int 
ctl_wstat(Spfile *f, Spstat *st) 
{
	return 1;
}

static int
push_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	char buf[128];

	snprintf(buf, sizeof buf, "thank you for reading push!\n");
	return cutstr(data, offset, count, buf, 0);
}

static int
pull_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	char buf[128];

	snprintf(buf, sizeof buf, "thank you for reading pull!\n");
	return cutstr(data, offset, count, buf, 0);
}
