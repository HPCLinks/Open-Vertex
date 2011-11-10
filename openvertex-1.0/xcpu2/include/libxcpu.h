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

typedef struct Xpnode Xpnode;
typedef struct Xpnodeset Xpnodeset;
typedef struct Xpnodeerror Xpnodeerror;
typedef struct Xpsession Xpsession;
typedef struct Xpsessionset Xpsessionset;
typedef struct Xpcommand Xpcommand;
typedef struct Xpproc Xpproc;


struct Xpnode {
	char*		name;
	char*		addr;
	char*		arch;
	char*		status;
	int		numjobs;
	void*		data; 
};

struct Xpnodeset {
	int		size;
	int		len;
	Xpnode*		nodes;
};

struct Xpnodeerror {
	Xpnode* 	node;
	char* 		ename;
	int 		ecode;
	Xpnodeerror* 	next;
};

struct Xpsessionset {
	int		size;
	int		len;
	Xpsession**	sessions;
};

enum {
	/* Xpcommand flags */
	LineOut		= 1,
	CopyShlib	= 2,
	NoCopy		= 4,
	Wait		= 256,	 /* waiting for command to finish */
};

struct Xpcommand {
	/* set by the user */
	int		flags;
	int		nspawn;		/* number of sessions to be spawned from front node */
	char*		exec;		/* name of the executable to run */
	char*		argv;
	char*		env;
	char*		jobid;
	char*		ns;		/* command namespace */
	int		lidstart;
	char*		archdir;

	void		(*stdout_cb)(Xpsession *, u8 *, u32);
	void		(*stderr_cb)(Xpsession *, u8 *, u32);
	void		(*wait_cb)(Xpsession *, u8 *, u32);

	/* set by the code */
	Xpnodeset*	nodes;
	Xpsessionset*	sessions;
	Spuser*		user;
	Xkey*		userkey;

	/* implementation specific */
	int		tcnt;
	char*		ename;
	int		ecode;
	int		signo;
	Spsrv*		srv;
	int		nsrvconns;
};

enum {
	Unknown,
	Running,
	Sleeping,
	Zombie,
	Stopped,
	Waiting,
	Paging,
};

struct Xpproc {
	Xpnode*		node;
	char*		xcpujid;
	char*		xcpusid;

	int		pid;
	char*		cmdline;	/* command line */
	int		state;		/* process status */
	int		ppid;		/* parent pid */
	Xpproc*		parent;		/* parent Xpproc (can be NULL) */
	int		pgrp;		/* process group */
	int		psid;		/* session ID */
	char*		tty;		/* process tty */
	int		tpgid;		/* process group of the tty owner */

	long long int	utime;		/* time in milliseconds in user mode */
	long long int	stime;		/* time in milliseconds in kernel mode */
	struct timeval	starttime;	/* process start time */
	int		priority;	/* process priority */
	int		nice;		/* nice value */
	char*		wchan;		/* name of the system call the process blocked on */
	
	int		euid;		/* effective user */
	int		suid;		/* saved user */
	int		fsuid;		/* filesystem access user */
	int		egid;		/* effective group */
	int		sgid;		/* saved group */
	int		fsgid;		/* filesystem access group */

	long long	vmsize;		/* total size in bytes */
	long long	rssize;		/* RSS size in bytes */
	long long	shsize;		/* shared memory size in bytes */
	long long	txtsize;	/* text size in bytes */
	long long	datsize;	/* data size in bytes */
};

Xpnode *xp_node_create(char *name, char *addr, char *arch, char *status, int numjobs);
void xp_node_destroy(Xpnode *);
Spcfsys *xp_node_mount(Xpnode *nd, Spuser *user, Xkey *key);

Xpnodeset *xp_nodeset_create(void);
void xp_nodeset_destroy(Xpnodeset *);
Xpnodeset *xp_nodeset_from_string(char *);
char *xp_nodeset_to_string(Xpnodeset *);
Xpnodeset *xp_nodeset_list(char *);
Xpnodeset *xp_nodeset_list_by_state(char *server, char *state);
Xpnodeset *xp_nodeset_list_by_arch(char *server, char *arch);
Xpnodeset *xp_nodeset_list_by_min_jobs(char *server, int minjobs);
Xpnodeset *xp_nodeset_list_by_max_jobs(char *server, int maxjobs);
int xp_nodeset_add(Xpnodeset *, Xpnode *);
int xp_nodeset_append(Xpnodeset *, Xpnodeset *);
int xp_nodeset_filter_by_node(Xpnodeset *, Xpnodeset *, char *nodelist);
int xp_nodeset_filter_by_state(Xpnodeset *, Xpnodeset *, char *state);
int xp_nodeset_iterate(Xpnodeset *, int (*itcb)(Xpnode *, void *), void *);
void xp_nodeerror_print(char *prog);

Xpnode *xp_session_get_node(Xpsession *);
char *xp_session_get_id(Xpsession *);
int xp_session_get_localaddr(Xpsession *s, char *buf, int buflen);

Xpcommand *xp_command_create(Xpnodeset *, Spuser *, Xkey *);
int xp_command_split_by_arch(Xpcommand *, Xpcommand ***);
void xp_command_destroy(Xpcommand *);
Xpcommand *xp_command_by_jobid(Xpnodeset *, char *);
int xp_command_exec(Xpcommand *);
int xp_command_wait(Xpcommand *);
int xp_commands_wait(int ncmds, Xpcommand **);
int xp_command_kill(Xpcommand *, int);
int xp_command_wipe(Xpcommand *);
int xp_command_send(Xpcommand *, u8 *data, u32 datalen);
int xp_command_close_stdin(Xpcommand *);

int xp_proc_list(Xpnodeset *, Spuser *, Xkey *, Xpproc **);
int xp_proc_kill(Xpproc *, Spuser *, Xkey *, int);

int xp_defaultuser(Spuser **puser, Xkey **pkey);
int xp_user_add(Xpnodeset *nds, char *adminkey, char *uname, uid_t uid, 
		char *gname, char *ukey);
int xp_user_del(Xpnodeset *nds, char *adminkey, char *uname);
int xp_user_flush(Xpnodeset *nds, char *adminkey);
int xp_user_add_group(Xpnodeset *nds, char *adminkey, char *uname, char *gname);
int xp_user_del_group(Xpnodeset *nds, char *adminkey, char *uname, char *gname);
int xp_getpwent(Xpnode *nd, char *adminkey, char ***pwent);
int xp_group_add(Xpnodeset *nds, char *adminkey, char *gname, gid_t gid);
int xp_group_del(Xpnodeset *nds, char *adminkey, char *gname);
int xp_group_flush(Xpnodeset *nds, char *adminkey);
int xp_getgrent(Xpnode *nd, char *adminkey, char ***grent);
