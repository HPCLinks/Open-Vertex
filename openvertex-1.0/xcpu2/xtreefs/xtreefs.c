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
#include <dirent.h>
#include "spfs.h"
#include "spclient.h"
#include "strutil.h"

#include "xcpu.h"
#include "queue.h"
#include "xtreefs.h"


/* root: just show what's there. qid is ino. Just create the files.
 * root is always named. cache whole files to start. requests from clients
 * go into queue. 
 */
Spdirops dir_ops = {
	.first = dir_first,
	.next = dir_next,
	.read = dir_read
};

Spfileops data_ops = {
	.read = data_read,
};

Spuser *user;
Spuserpool *up;

struct Worker {
	char *ip;
	int  port;
};

Spsrv 	*srv;
Spfile 	*root;
char 	*defip = "127.0.0.1";
char 	*defproto = "tcp";
char	*service = "tcp!*!20003";
char 	*cfg = "xbootfs.conf";
int		defport = 20002;
unsigned int	debuglevel = 0;
Queue *avail;
char *rootdir = 0, *netaddress = 0;
int filelen = 0;
char *data = 0;
Spfile *datafile;
int serve = 0;

static void 
usage(char *name) {
	fprintf(stderr, "usage: %s [-d] [-D debuglevel] [-p port] <-f file> | <-n netaddr>\n", name);
	exit(1);
}

static void
debug(int level, char *fmt, ...)
{
	va_list arg;

	if (!(debuglevel & level))
		return;
	va_start(arg, fmt);
	vfprintf(stderr, fmt, arg);
	va_end(arg);
}

void
timeout(int whatever)
{
	fprintf(stderr, "All done (%d) ... leaving\n", whatever);
	exit(0);
}

void
change_user(Spuser *user)
{
	sp_change_user(user);
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
fsinit(char *path)
{      
	root = spfile_alloc(NULL, "", 0555 | Dmdir, Qroot, &dir_ops, strdup(path));
	root->parent = root;
	spfile_incref(root);
	root->atime = root->mtime = time(NULL);
	root->uid = root->muid = user;
	root->gid = user->dfltgroup;
	/* structure of spfs kind of requires this */
	scandir(root);
}

static off_t
filesize(char *file)
{
	struct stat buf;

	if (stat(file, &buf) < 0)
		return -1;
	return buf.st_size;
}

static char *
dothefile(char *filename)
{
	int fd;

	filelen = filesize(filename);

	if (filelen == -1) {
		perror("no file?");
		exit(1);
	}
	data = malloc(filelen);
	if (! data){
		perror("malloc");
		exit(1);
	}
	fd = open(filename, O_RDONLY);
	if (fd < 0){
		perror("open");
		exit(1);
	}
	if (read(fd, data, filelen) < filelen){
		perror("read");
		exit(1);
	}
	return filename;
}

int
netfile(Spcfsys *Client, char *name, char **data)
{
	Spwstat *spc_stat(Spcfsys *fs, char *path);
	Spwstat *stat;
	u64 len;
	Spcfid *file;

	stat = spc_stat(Client, name);
	if (!stat){
		debug(1, "Stat of :%s: fails\n", name);
		return -1;
	}
	len = stat->length;

	file = spc_open(Client, name, Oread);
	if (!file){
		debug(1, "Open of :%s: fails\n", name);
		return -1;
	}

	*data = malloc(len);
	if (!*data)
		return -1;
	memset(*data, 0, len);

	if ((len = spc_read(file, (u8 *) *data, len, 0)) < 0){
		debug(1, "Read of :%s: fails\n", name);
		return -1;
	}

	return len;
}

void server()
{

}

Spcfsys * client()
{
	int redirlen, worker = 0;
	char *action;
	char *dataaddress;
	int ecode;
	char *ename;
	Spcfsys *Client = NULL;

	Client = spc_netmount(netaddress, user, defport, NULL, NULL);
	if (!Client)
		goto error;
	redirlen = netfile(Client, "redir", &action);
	if (redirlen <= 0)
		goto error;
	debug(1, "redir reads as :%s:\n", action);
	/* get the data server address */
	if (!strcmp(action, "me"))
		dataaddress = netaddress;
	else if (!strcmp(action, "you")){
		dataaddress = netaddress;
		worker = 1;
	} else {
		char *portname;
		dataaddress = action;
		portname = strchr(action, '!');
		if (! portname)
			goto error;
		defport = strtoul(portname, 0, 0);
		spc_umount(Client);
		debug(1, "Client: mount tcp!%s!%s\n", dataaddress, portname);
		Client = spc_netmount(dataaddress, user, defport, NULL, NULL);
		if (!Client)
			goto error;
	}
	debug(1, "Try to read data, then %s\n", worker ? 
			"become worker" : "exit");
	filelen = netfile(Client, "data", &data);
	if (filelen <= 0)
		goto error;
	debug(1, "Got the data, %d bytes\n", filelen);

	if (!worker) {
		/* we don't become a worker so exit */
		printf("all done, bye\n");
		exit(0);
	}

	return Client;

error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "%s\n", ename);
	return Client;
}
int
main(int argc, char **argv)
{
	int c, ecode;
	char *s, *ename;
	extern Spuserpool *sp_unix_users;

	while ((c = getopt(argc, argv, "dsD:p:r:n:")) != -1) {
		switch (c) {
		case 'd':
			spc_chatty = 1;
			break;
		case 'p':
			defport = strtol(optarg, &s, 10);
			if(*s != '\0')
				usage(argv[0]);
			break;
		case 'D':
			debuglevel = strtol(optarg, &s, 10);
			if(*s != '\0')
				usage(argv[0]);
			break;
		case 'n':
			netaddress = optarg;
			break;

		case 'r':
			rootdir=optarg;
		case 's':
			serve = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	if ((!rootdir) && (!netaddress)) {
		fprintf(stderr, "please supply either -r or -n arguments\n");
		usage(argv[0]);
	}

	if (optind != argc)
		usage(argv[0]);

	up = sp_unix_users;
	user = up->uid2user(up, getuid());
	if (!user) {
		fprintf(stderr, "user not found\n");
		exit(1);
	}

	avail = qalloc();
	if (!avail)
		goto error;

	signal(SIGALRM, timeout);
	if (netaddress) {
		Spcfsys *Client;

		if ((Client = client()) == NULL) {
			exit(1);
		}
	}


	fsinit(rootdir);

	srv = sp_socksrv_create_tcp(&defport);
	if (!srv)
		goto error;
	srv->debuglevel = debuglevel > 1;
	srv->dotu = 1;
	spfile_init_srv(srv, root);
	sp_srv_start(srv);
#ifdef NOT

	/* now mount me */
	mountmyselfatcache();
#endif
	/* FixME: re-queue ourself ? */

	while (1){
		sp_poll_once();
	}


	return 0;

error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "%s\n", ename);
	return -1;
}

static int
data_read(Spfilefid *fid, u64 offset, u32 count, u8 *buf, Spreq *req)
{
	if (offset > filelen)
		return 0;
	if ((offset + count) > filelen)
		count = filelen - offset;
	memcpy(buf, &data[offset], count);
	return count;
}

#if 0
/* later */
/* on f-ing thing at a time */

static int
dir_read(Spfilefid *fid, u64 offset, u32 count, u8 *buf, Spreq *req)
{
	DIR *d;
	struct dirent de;
	Spfile *f = fid->file;
	int ret;
	struct Spstat *s = (struct Spstat *)buf;

	d = opendir(f->aux);
	seekdir(d, offset);

	ret = readdir(d);
	closedir(d);
	s->size = sizeof(*s) + de.d_reclen;
	s->type = Dmdir;
	s->mode = 0666;
	s->name.len = de.d_reclen;
	s->name.str = buf + sizeof(*s);
	strcpy(buf + sizeof(*s), de.d_name);

	return sizeof(*s) + de.d_reclen;
}
#endif