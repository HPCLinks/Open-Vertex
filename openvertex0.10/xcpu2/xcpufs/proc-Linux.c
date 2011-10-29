#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <asm/param.h>
#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "xcpu.h"
#include "libxauth.h"
#include "xcpufs.h"

typedef struct Pentry Pentry;

struct Pentry {
	int		pid;
	int		idfound;
	char**		pdescr;
	Pentry*		parent;
	Pentry*		next;
};

/* all fields in the order returned */
enum {
	Pid = 0,	/* process id */
	Cmdline,	/* command line */
	State,		/* process state (RSZSP) */
	Ppid,		/* parent pid */
	Pgrp,		/* process group */
	Psid,		/* process session */
	Tty,		/* process tty */
	Tpgid,		/* process group of the tty owner */
	Utime,		/* time in milliseconds in user mode */
	Stime,		/* time in milliseconds in kernel mode */
	Etime,		/* elapsed time */
	Priority,
	Nice,
	Wchan,		/* system call name the process is blocked on */
	Euid,		/* effective user id */
	Suid,		/* saved user id */
	Fsuid,		/* filesystem access user id */
	Egid,		/* effective group id */
	Sgid,		/* saved group id */
	Fsgid,		/* filesystem access user id */
	Vmsize,		/* virtual memory size in bytes (-1 if unknown) */
	Rssize,		/* resident size in bytes (-1 if unknown) */
	Shsize,		/* shared memory size in bytes (-1 if unknown) */
	Txtsize,	/* text size in bytes (-1 if unknown) */
	Datsize,	/* data size in bytes (-1 if unknown) */
	Xcpusid,	/* xcpu session id */
	Xcpujid,	/* xcpu job id */
	Proclast,	/* how many elements in total */
};

/* names of the fields (order should match the enum above) */
char *procnames[] = {
	"pid",
	"(cmdline)",
	"state",
	"ppid",
	"pgrp",
	"psid",
	"tty",
	"tpgid",
	"utime",
	"stime",
	"etime",
	"priority",
	"nice",
	"wchan",
	"euid",
	"suid",
	"fsuid",
	"egid",
	"sgid",
	"fsgid",
	"vmsize",
	"rssize",
	"shsize",
	"txtsize",
	"datsize",
	"xcpusid",
	"xcpujid",
};

int stat2all[] = {
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, -1, 20, 21, 22, 
	23, 24, 25, 26, 27, 28, 29, 30, 
	31, 32, 33, 34, 35, 36, 37, 38, 
	39,
};

int statm2all[] = {
	40, 41, 42, 43, 44, 45, 46,
};

struct {
	char*	fldname;
	int	idx[5];
} status2all[] = {
	{ "Uid:", { -1, 14, 15, 16, -1} },
	{ "Gid:", { -1, 17, 18, 19, -1} },
};

extern char *environ;

static long long jiffspersec;	/* set by getprocs: jiffies per second */
static long long int uptime;	/* set by getprocs: time in jiffies from boot */

#define NELEM(x) (sizeof(x)/sizeof(x[0]))

static Pentry *parseproc(char *pid, Pentry **pentries);
static int process_stat(char *pid, char **pdescr);
static int process_statm(char *pid, char **pdescr);
static int process_status(char *pid, char **pdescr);
static int process_cmdline(char *pid, char **pdescr);
static int process_wchan(char *pid, char **pdescr);
static void pdescr_copy(char **pdescr, char **str);
static void set_uptime(void);
static void set_jiffies(void);
static void find_pentry_ids(Pentry *pe);

char *
getprocs(void)
{
	int i, ppid;
	char *ret, *s;
	DIR *d;
	struct dirent *de;
	Pentry *pentries, *pe, *pe1;

	pentries = NULL;
	ret = NULL;
	pdescr_copy(procnames, &ret);

	set_jiffies();
	set_uptime();
	d = opendir("/proc");
	if (!d) {
		sp_uerror(errno);
		return NULL;
	}

	while ((de = readdir(d)) != NULL) {
		if (*de->d_name < '0' || *de->d_name > '9')
			continue;

		parseproc(de->d_name, &pentries);
	}
	closedir(d);

	/* find the parents of the processes */
	for(pe = pentries; pe != NULL; pe = pe->next) {
		ppid = strtol(pe->pdescr[Ppid], &s, 10);
		if (*s != '\0')
			continue;

		for(pe1 = pentries; pe1 != NULL; pe1 = pe1->next)
			if (pe1->pid == ppid) {
				pe->parent = pe1;
				break;
			}
	}

	/* find processes session and job ids */
	for(pe = pentries; pe != NULL; pe = pe->next)
		find_pentry_ids(pe);

	/* output the rocess data */
	pe = pentries;
	while (pe != NULL) {
		pdescr_copy(pe->pdescr, &ret);
		for(i = 0; i < Proclast; i++)
			free(pe->pdescr[i]);

		pe1 = pe->next;
		free(pe);
		pe = pe1;
	}

	return ret;
}

static void
pdescr_copy(char **pdescr, char **str)
{
	int i, n, slen;
	char *s;

	for(n = 0, i = 0; i < Proclast; i++)
		if (pdescr[i])
			n += strlen(pdescr[i]) + 1;
		else
			n += 3;

	if (*str)
		slen = strlen(*str);
	else
		slen = 0;

	s = realloc(*str, slen + n + 5);
	if (!s)
		return;

	*str = s;
	s += slen;
	*(s++) = '(';
	for(i = 0; i < Proclast; i++) {
		if (pdescr[i]) {
			n = strlen(pdescr[i]);
			memmove(s, pdescr[i], n);
			s += n;
		} else {
			memmove(s, "''", 2);
			s += 2;
		}

		*(s++) = ' ';
	}

	*(s++) = ')';
	*(s++) = ' ';
	*(s++) = '\n';
	*(s++) = '\0';
}

static Pentry *
parseproc(char *pid, Pentry **pentries)
{
	int i;
	char buf[1024];
	char *s, **pdescr;
	Pentry *pe, *p;
	Xsession *xs;

	pe = malloc(sizeof(*pe));
	if (!pe)
		return NULL;

	pe->pid = -1;
	pe->idfound = 0;
	pe->pdescr = NULL;
	pe->parent = NULL;
	pe->next = NULL;

	pdescr = calloc(Proclast, sizeof(char *));
	if (!pdescr)
		return NULL;

	if (process_cmdline(pid, pdescr) < 0)
		goto error;

	if (process_stat(pid, pdescr) < 0)
		goto error;

	if (process_statm(pid, pdescr) < 0)
		goto error;

	if (process_status(pid, pdescr) < 0)
		goto error;

	if (process_wchan(pid, pdescr) < 0)
		goto error;


	pe->pdescr = pdescr;
	pe->pid = strtol(pdescr[Pid], &s, 10);
	if (*s != '\0')
		goto error;

	/* find out if this is a main process of a session */
	for(xs = sessions; xs != NULL; xs = xs->next)
		if (xs->pid == pe->pid) {
			sprintf(buf, "%d", xs->sid);
			pe->pdescr[Xcpusid] = strdup(buf);
			snprintf(buf, sizeof(buf), "%s/%d", xs->gid, xs->lid);
			pe->pdescr[Xcpujid] = strdup(buf);
			break;
		}

	/* add the process in the appropriate place */
	if (!*pentries)
		*pentries = pe;
	else {
		for(p = *pentries; p->next != NULL; p = p->next)
			if (p->next->pid > pe->pid)
				break;

		pe->next = p->next;
		p->next = pe;
	}
	
	return pe;

error:
	for(i = 0; i < Proclast; i++) 
		free(pdescr[i]);

	free(pdescr);
	free(pe);
	return NULL;
}

static char *
get_tty_name(char *tty_nr)
{
	int dev, major, minor;
	char *s;
	char buf[32];

	dev = strtol(tty_nr, &s, 10);
	if (*s != '\0')
		goto unknown;

	major = (dev&0xfff00) >> 8;
	minor = (dev&0xff) | ((dev>>12) & 0xfff00);
	switch (major) {
	case 2:
		sprintf(buf, "ptyp%d", minor);
		break;

	case 3:
		sprintf(buf, "ttyp%d", minor);
		break;

	case 4:
		if (minor < 64)
			sprintf(buf, "tty%d", minor);
		else
			sprintf(buf, "ttyS%d", minor);
		break;

	case 5:
		if (minor < 64)
			goto unknown;
		else
			sprintf(buf, "cua%d", minor);
		break;

	case 136:
	case 137:
	case 138:
	case 139:
	case 140:
		sprintf(buf, "pts/%d", minor + (major - 136) * 256);
		break;

	default:
		goto unknown;
	}

	return strdup(buf);
	
unknown:
	return strdup("??");
}

static char *
get_time(char *sjiff)
{
	long long int n;
	long long int ms;
	char *s, buf[32];

	n = strtoll(sjiff, &s, 10);
	if (*s != '\0')
		goto error;

	ms = (n * 1000) / jiffspersec;
	sprintf(buf, "%lld", ms);
	return strdup(buf);


error:
	return strdup("-1");
}

static char *
get_etime(char *sjiff)
{
	int n;
	long long int ms;
	char *s, buf[32];

	n = strtol(sjiff, &s, 10);
	if (*s != '\0')
		goto error;

	n = uptime - n;
	ms = ((long long int) n * 1000) / jiffspersec;
	sprintf(buf, "%lld", ms);
	return strdup(buf);


error:
	return strdup("-1");
}

static char *
get_size(char *sz)
{
	int n;
	char *s, buf[32];

	n = strtol(sz, &s, 10);
	if (*s != '\0')
		return strdup("-1");

	sprintf(buf, "%lu", n * sysconf(_SC_PAGESIZE));
	return strdup(buf);
}

static int
process_stat(char *pid, char **pdescr)
{
	int n, fd;
	char fname[64];
	char buf[8192], b[16];
	char **toks, *s, *p, *t;

	/* For reference: from linux-2.6.17 kernel code:
	  	res = sprintf(buffer,"%d (%s) %c %d %d %d %d %d %lu %lu \
%lu %lu %lu %lu %lu %ld %ld %ld %ld %d 0 %llu %lu %ld %lu %lu %lu %lu %lu \
%lu %lu %lu %lu %lu %lu %lu %lu %d %d %lu %lu\n",
		task->pid,
		tcomm,
		state,
		ppid,
		pgid,
		sid,
		tty_nr,
		tty_pgrp,
		task->flags,
		min_flt,
		cmin_flt,
		maj_flt,
		cmaj_flt,
		cputime_to_clock_t(utime),
		cputime_to_clock_t(stime),
		cputime_to_clock_t(cutime),
		cputime_to_clock_t(cstime),
		priority,
		nice,
		num_threads,
		start_time,
		vsize,
		mm ? get_mm_rss(mm) : 0,
	        rsslim,
		mm ? mm->start_code : 0,
		mm ? mm->end_code : 0,
		mm ? mm->start_stack : 0,
		esp,
		eip,
		task->pending.signal.sig[0] & 0x7fffffffUL,
		task->blocked.sig[0] & 0x7fffffffUL,
		sigign      .sig[0] & 0x7fffffffUL,
		sigcatch    .sig[0] & 0x7fffffffUL,
		wchan,
		0UL,
		0UL,
		task->exit_signal,
		task_cpu(task),
		task->rt_priority,
		task->policy);
	*/
	snprintf(fname, sizeof(fname) - 1, "/proc/%s/stat", pid);
	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return -1;

	n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n <= 0) 
		return -1;

	buf[n] = '\0';
	s = strchr(buf, ' ');
	*(s++) = '\0';
	pdescr[Pid] = strdup(buf);
	p = strrchr(s, ')');
	if (pdescr[Cmdline] == NULL) {
		*p = '\0';
		t = quotestrdup(s + 1);
		pdescr[Cmdline] = sp_malloc(strlen(t) + 3);
		if (!pdescr[Cmdline])
			return -1;

		sprintf(pdescr[Cmdline], "(%s)", t);
		free(t);
	}

	p += 2;	/* skip ) and space */

	n = tokenize(p, &toks);
	if (n < 0)
		return -1;

	if (n < 38) {
		free(toks);
		return -1;
	}

	pdescr[State] = strdup(toks[0]);
	pdescr[Ppid] = strdup(toks[1]);
	pdescr[Pgrp] = strdup(toks[2]);
	pdescr[Psid] = strdup(toks[3]);
	pdescr[Tty] = get_tty_name(toks[4]);
	pdescr[Tpgid] = strdup(toks[5]);
	pdescr[Utime] = get_time(toks[11]);
	pdescr[Stime] = get_time(toks[12]); 
	pdescr[Etime] = get_etime(toks[19]); // TODO add computer boot time

	n = strtol(toks[15], &p, 10);
	if (*p == '\0')
		n -= 15;
	else
		n = -1;

	sprintf(b, "%d", n);
	pdescr[Priority] = strdup(b);
	pdescr[Nice] = strdup(toks[16]);
	pdescr[Vmsize] = strdup(toks[20]);
	pdescr[Rssize] = get_size(toks[21]);
	free(toks);

	return 0;
}

static int
process_statm(char *pid, char **pdescr)
{
	int n, fd;
	char fname[64];
	char buf[1024];
	char **toks;

	snprintf(fname, sizeof(fname) - 1, "/proc/%s/statm", pid);
	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return -1;

	n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n <= 0) 
		return -1;

	buf[n] = '\0';
	n = tokenize(buf, &toks);
	if (n < 0)
		return -1;

	if (n < 5)
		return -1;

	pdescr[Shsize] = get_size(toks[2]);
	pdescr[Txtsize] = get_size(toks[3]);
	pdescr[Datsize] = get_size(toks[5]);

	return 0;
}

static int
process_status(char *pid, char **pdescr)
{
	int i, j, m, n;
	FILE *f;
	char fname[64];
	char buf[1024];
	char **toks;

	snprintf(fname, sizeof(fname) - 1, "/proc/%s/status", pid);
	f = fopen(fname, "r");
	if (!f) 
		return -1;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		n = tokenize(buf, &toks);
		if (n < 0) {
			fclose(f);
			return -1;
		}

		if (n < 2) {
			free(toks);
			continue;
		}

		for(i = 0; i < NELEM(status2all); i++) {
			if (strcmp(status2all[i].fldname, toks[0]) != 0)
				continue;

			for(j = 0; j < NELEM(status2all[i].idx); j++) {
				m = status2all[i].idx[j];
				if (m >= 0) {
					if (n < j + 1) {
						free(toks);
						fclose(f);
						return -1;
					}

					pdescr[m] = strdup(toks[j + 1]);
				}
			}
		}

		free(toks);
	}

	fclose(f);
	return 0;
}

static int
process_cmdline(char *pid, char **pdescr)
{
	int n, fd, l;
	char fname[64];
	char buf[8192], *cmd;
	char *p, *s, *t;

	snprintf(fname, sizeof(fname) - 1, "/proc/%s/cmdline", pid);
	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		sp_uerror(errno);
		free(cmd);
		return -1;
	}

	buf[sizeof(buf) - 1] = '\0';
	n = read(fd, buf, sizeof(buf) - 2);
	if (n < 0) {
		sp_uerror(errno);
		close(fd);
		return -1;
	}

	close(fd);
	if (n == 0)
		return 0;

	if (buf[n-1] != '\0') 
		buf[n++] = '\0';

	buf[n] = '\0';
	cmd = strdup("(");
	l = strlen(cmd);

	s = buf;
	while (*s != '\0') {
		t = quotestrdup(s);
		if (!t) {
			free(cmd);
			return -1;
		}

		n = strlen(t);
		p = realloc(cmd, n + l + 2);
		if (!p) {
			sp_werror(Enomem, ENOMEM);
			free(cmd);
			return -1;
		}

		cmd = p;
		memmove(cmd + l, t, n);
		l += n;
		cmd[l++] = ' ';
		free(t);
		s += strlen(s) + 1;
	}

	if (cmd[l - 1] == ' ')
		l--;

	cmd[l++] = ')';
	cmd[l] = '\0';
	pdescr[Cmdline] = cmd;
	return 0;
}

static int
process_wchan(char *pid, char **pdescr)
{
	int n, fd;
	char fname[64];
	char buf[1024];

	snprintf(fname, sizeof(fname) - 1, "/proc/%s/wchan", pid);
	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return 0;

	n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n <= 0) 
		return 0;

	buf[n] = '\0';
	pdescr[Wchan] = strdup(buf);
	return 0;
}

static void
set_jiffies(void)
{
	unsigned long *ep;

	if (jiffspersec) 
		return;

	/* try to use the ELF notes */
	ep = (unsigned long *) environ;
	while (*ep++)
		;

	while (*ep) {
		if (ep[0] == 17) {
			jiffspersec = ep[1];
			return;
		}

		ep += 2;
	}

	/* no luck, use HZ */
	jiffspersec = HZ;
}

static void
set_uptime(void)
{
	int fd, n;
	double utime;
	char buf[128];

	fd = open("/proc/uptime", O_RDONLY);
	if (fd < 0)
		return;

	n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n <= 0)
		return;

	buf[n] = '\0';
	utime = strtod(buf, NULL);
	uptime = utime * jiffspersec;
}


static void
find_pentry_ids(Pentry *pe)
{
	if (pe->idfound)
		return;

	if (!pe->parent)
		return;

	if (!pe->parent->idfound)
		find_pentry_ids(pe->parent);

	if (pe->parent->pdescr[Xcpusid])
		pe->pdescr[Xcpusid] = strdup(pe->parent->pdescr[Xcpusid]);

	if (pe->parent->pdescr[Xcpujid])
		pe->pdescr[Xcpujid] = strdup(pe->parent->pdescr[Xcpujid]);

	pe->idfound = 1;
}
