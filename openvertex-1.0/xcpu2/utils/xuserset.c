/*
 * Copyright (C) 2007 by Latchesar Ionkov <lucho@ionkov.net>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <signal.h>
#include <dirent.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "libxauth.h"
#include "libxcpu.h"
#include "xcpu.h"

extern int spc_chatty;

void
usage(char *name)
{
	fprintf(stderr, "usage: %s [-h] add [-A adminkey] {-a | nodeset} user uid group key\n", name);
	fprintf(stderr, "       %s      delete [-A adminkey] {-a | nodeset} user\n", name);
	fprintf(stderr, "       %s      flush [-A adminkey] {-a | nodeset}\n\n", name);
	fprintf(stderr, "       %s      addgroup [-A adminkey] {-a | nodeset} user group\n", name);
	fprintf(stderr, "       %s      delgroup [-A adminkey] {-a | nodeset} user group\n", name);
	fprintf(stderr, "where: \n");
	fprintf(stderr, "\tnodeset is the set of nodes to issue the command to\n");
	fprintf(stderr, "\tif -a is used, contact statfs and get a list of all nodes that are up\n");
	fprintf(stderr, "\tuser is the user name of the user\n");
	fprintf(stderr, "\tuid is the numeric user id of the user on the remote machine\n");
	fprintf(stderr, "\tgroup is the group this user belongs to\n");
	fprintf(stderr, "\tkey is the public key of that user (usually id_rsa.pub)\n");
	fprintf(stderr, "\n\tadminkey is the private key of the admin user (usually /etc/xcpu/admin_key)\n");

	fprintf(stderr, "\nexample: %s add 192.168.19.2 root 0 xcpu-admin ~/.ssh/id_rsa.pub\n", name);
	fprintf(stderr, "\t: %s delete 192.168.19.2 root\n", name);
	exit(1);
}

static inline
int get_user_key(char *keypath, char *key, int keysize)
{
	int fd, n;
	char *s;

	fd = open(keypath, O_RDONLY);
	if (fd < 0)
		return -1;

	n = read(fd, key, keysize-1);
	if (n < 0)
		return -1;

	s = strchr(key, '\n');
	if (s)
		*s = '\0';
	else
		*(key+n) = '\0';
	close(fd);
	return 0;
}

int
main(int argc, char **argv)
{
	int c, ecode, port = STAT_PORT;
	u32 userid;
	char cmd[9], ukeypath[1024], userkey[4096];
	char *nodeset, *ename, *username, *groupname;
	char *adminkey = NULL, *end;
	Xpnodeset *nds, *nds2;
	int allflag = 0, passwdfile = 0;
	struct passwd *pw;
	struct group *gr;
	struct pwent {
		char *pw_name;
		uid_t pw_uid;
		gid_t pw_gid;
		char *pw_key;
		struct pwent *next;
	} *users, *head;

	while((c = getopt(argc, argv, "aA:dhup")) != -1) {
		switch(c) {
		case 'd':
			spc_chatty = 1;
			break;
		case 'A':
			adminkey = strdup(optarg);
			break;
		case 'a':
			allflag++;
			break;
		case 'u':
			passwdfile++;
			break;
		case 'p':
			port = strtol(optarg, &end, 10);
			if (*end != '\0')
				usage(argv[0]);
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (argc < 2)
		usage(argv[0]);

	snprintf(cmd, 9 * sizeof(char), "%s", argv[optind++]);
	if (!strcmp("add", cmd) && !passwdfile) {
		if (argc < 7)
			usage(argv[0]);
	} else if (!strcmp("delete", cmd) && !passwdfile) {
		if (argc < 4)
			usage(argv[0]);
	} else if (!strcmp("addgroup", cmd) || !strcmp("delgroup", cmd)) {
		if (argc < 5)
			usage(argv[0]);		
	} else if (!strcmp("flush", cmd) || passwdfile)
		;
	else
		usage(argv[0]);

	if (!allflag && ((nodeset = getenv("NODES")) == NULL)) {
		if ((argc - optind) < 1 && !passwdfile)
			usage(argv[0]);
		nodeset = argv[optind++];
	}

	if (allflag) {
		char statserver[32];
		sprintf(statserver, "localhost!%d", port);
		nds = xp_nodeset_list(NULL);
		if(nds == NULL)
			nds = xp_nodeset_list(statserver);
		if (nds != NULL) {
			nds2 = xp_nodeset_create();
			if (nds2 != NULL) {
				if (xp_nodeset_filter_by_state(nds2, nds, "up") >= 0) {
					free(nds);
					nds = nds2;
				} else {
					free(nds2);
				}
			} /* if filter is unsuccessful just use the full set */
		}
	} else
		nds = xp_nodeset_from_string(nodeset);

	if (!nds)
		goto error;

	if (!strcmp("flush", cmd)) {
		if (xp_user_flush(nds, adminkey) < 0)
			goto error;
	} else if (!strcmp("delete", cmd)) {
		if (passwdfile) {
			setpwent();
			while ((pw = getpwent()) != NULL)
				xp_user_del(nds, adminkey, pw->pw_name);
			endpwent();
		} else {
			if ((argc - optind) < 1)
				usage(argv[0]);
			username = argv[optind++];
			if (xp_user_del(nds, adminkey, username) < 0)
				return -1;
		}
	} else if (!strcmp("add", cmd)) {
		if (passwdfile) {
			setpwent();
			head = NULL;
			while ((pw = getpwent()) != NULL) {
				snprintf(ukeypath, sizeof(ukeypath), "%s/.ssh/id_rsa.pub", pw->pw_dir);
				if (!access(ukeypath, R_OK)) {
					users = (struct pwent *)malloc(sizeof(struct pwent));
					users->pw_name = strdup(pw->pw_name);
					users->pw_uid = pw->pw_uid;
					users->pw_gid = pw->pw_gid;					
					users->pw_key = strdup(ukeypath);
					users->next = head;
					head = users;
				}
			}
			endpwent();

			for(; users; users = users->next) {
				if (get_user_key(users->pw_key, userkey, sizeof(userkey)) < 0)
					continue;
			
				if ((gr = getgrgid(users->pw_gid)) == NULL)
					continue;
			
				xp_user_add(nds, adminkey, users->pw_name, users->pw_uid,
					    gr->gr_name, userkey);
			}
		} else {
			if ((argc - optind) < 4)
				usage(argv[0]);
			username = argv[optind++];
			userid = strtol(argv[optind++], NULL, 10);
			groupname = argv[optind++];
			
			if (get_user_key(argv[optind], userkey, sizeof(userkey)) < 0) {
				sp_suerror("get_user_key", errno);
				goto error;
			}
			
			if (xp_user_add(nds, adminkey, username, userid,
					groupname, userkey) < 0)
				return -1;
		}
	} else { /* group operations */
		if ((argc - optind) < 2)
			usage(argv[0]);
		username = argv[optind++];
		groupname = argv[optind++];

		if (!strcmp("addgroup", cmd)) {
			if (xp_user_add_group(nds, adminkey, username,
					      groupname) < 0)
				return -1;
		} else { /* !strcmp("delgroup", cmd) */			
			if (xp_user_del_group(nds, adminkey, username,
					      groupname) < 0)
				return -1;
		}
	}
	return 0;
error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "Error: %s\n", ename);
	return -1;
}

