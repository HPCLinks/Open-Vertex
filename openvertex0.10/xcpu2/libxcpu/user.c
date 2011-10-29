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
#include <regex.h>
#include <math.h>
#include <sys/types.h>
#include <pwd.h>

#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "libxauth.h"
#include "libxcpu.h"
#include "xcpuimpl.h"

int
xp_defaultuser(Spuser **puser, Xkey **pkey)
{
	Spuser *adminuser = NULL;
	struct passwd *xcpu_admin;
	Xkey *adminkey = NULL;

	if (puser)
		*puser = NULL;

        if (*pkey)
                adminkey = *pkey;
        else
                adminkey = xauth_privkey_create("/etc/xcpu/admin_key");
        
	if (adminkey) {
		adminuser = sp_malloc(sizeof(*adminuser));
		if (!adminuser)
			goto error;
		adminuser->uname = strdup("xcpu-admin");
		xcpu_admin = getpwnam("xcpu-admin");
		if (xcpu_admin)
			adminuser->uid = xcpu_admin->pw_uid;
		else
			adminuser->uid = 65530;
	} else {
		adminuser = sp_unix_users->uid2user(sp_unix_users,
						    geteuid());
		if (!adminuser)
			goto error;

		adminkey = xauth_user_privkey();
		if (!adminkey)
			goto error;		
	}
	
	if (puser)	
		*puser = adminuser;
	if (pkey)
		*pkey = adminkey;
	return 0;
error:
	if (adminuser)	
		free(adminuser);

	if (adminkey)
		xauth_destroy(adminkey);
	return -1;
}

int
xp_user_add(Xpnodeset *nds, char *adminkey, char *uname, uid_t uid, char *gname, char *ukey)
{
	Xcmd *addcmd;
	Spstr *cmd;
	char *qkey;

	if (!nds)
		return -1;
	
	cmd = sp_malloc(sizeof(*cmd));
	cmd->len = 4096;
	cmd->str = sp_malloc(cmd->len);
	qkey = quotestrdup(ukey);
	snprintf(cmd->str, cmd->len, "user-add %s %d %s %s\n", uname, uid,
		 gname, qkey);
	free(qkey);
	addcmd = xcmd_init(cmd, adminkey);
	if (!addcmd)
		goto error;
	
	if (xp_nodeset_iterate(nds, xp_ctl_cmd, addcmd) > 0)
		goto error;

	xcmd_destroy(addcmd);
	return 0;
error:
	if (addcmd)
		xcmd_destroy(addcmd);

	xp_nodeerror_print("xp_user_add");
	return -1;
}

int
xp_user_del(Xpnodeset *nds, char *adminkey, char *uname)
{
	Xcmd *delcmd;
	Spstr *cmd;

	if (!nds)
		return -1;

	cmd = sp_malloc(sizeof(*cmd));
	cmd->len = 512;
	cmd->str = sp_malloc(cmd->len);
	snprintf(cmd->str, cmd->len, "user-del %s\n", uname);
	delcmd = xcmd_init(cmd, adminkey);
	if (!delcmd)
		goto error;
	
	if (xp_nodeset_iterate(nds, xp_ctl_cmd, delcmd) > 0)
		goto error;

	xcmd_destroy(delcmd);
	return 0;
error:
	if (delcmd)
		xcmd_destroy(delcmd);

	xp_nodeerror_print("xp_user_del");
	return -1;
}

int
xp_user_flush(Xpnodeset *nds, char *adminkey)
{
	Xcmd *flcmd;
	Spstr *cmd;

	if (!nds)
		return -1;
	
	cmd = sp_malloc(sizeof(*cmd));
	cmd->str = strdup("user-flush\n");
	cmd->len = strlen(cmd->str);
	flcmd = xcmd_init(cmd, adminkey);
	if (!flcmd)
		goto error;

	if (xp_nodeset_iterate(nds, xp_ctl_cmd, flcmd) > 0)
		goto error;

	xcmd_destroy(flcmd);
	return 0;
error:
	if (flcmd)
		xcmd_destroy(flcmd);

	xp_nodeerror_print("xp_user_flush");
	return -1;
}

int
xp_user_add_group(Xpnodeset *nds, char *adminkey, char *uname, char *gname)
{
	Xcmd *grpcmd;
	Spstr *cmd;

	if (!nds)
		return -1;
	
	cmd = sp_malloc(sizeof(*cmd));
	cmd->len = 1024;
	cmd->str = sp_malloc(cmd->len);
	snprintf(cmd->str, cmd->len, "user-add-group %s %s\n", uname, gname);
	grpcmd = xcmd_init(cmd, adminkey);
	if (!grpcmd)
		goto error;
	
	if (xp_nodeset_iterate(nds, xp_ctl_cmd, grpcmd) > 0)
		goto error;

	xcmd_destroy(grpcmd);
	return 0;
error:
	if (grpcmd)
		xcmd_destroy(grpcmd);

	xp_nodeerror_print("xp_user_add_group");
	return -1;
}

int
xp_user_del_group(Xpnodeset *nds, char *adminkey, char *uname, char *gname)
{
	Xcmd *grpcmd;
	Spstr *cmd;

	if (!nds)
		return -1;
	
	cmd = sp_malloc(sizeof(*cmd));
	cmd->len = 1024;
	cmd->str = sp_malloc(cmd->len);
	snprintf(cmd->str, cmd->len, "user-del-group %s %s\n", uname, gname);
	grpcmd = xcmd_init(cmd, adminkey);
	if (!grpcmd)
		goto error;
	
	if (xp_nodeset_iterate(nds, xp_ctl_cmd, grpcmd) > 0)
		goto error;

	xcmd_destroy(grpcmd);
	return 0;
error:
	if (grpcmd)
		xcmd_destroy(grpcmd);

	xp_nodeerror_print("xp_user_del_group");
	return -1;
}

int
xp_getpwent(Xpnode *nd, char *adminkey, char ***pwent)
{
	char *buf = NULL, **toks;
	int n, bufsize = 8192;
	Xkey *akey = NULL;
	Spuser *auser = NULL;
        Spcfsys *fs = NULL;
        Spcfid *fid = NULL;

	if (adminkey) {
		akey = xauth_privkey_create(adminkey);
		if (!akey)
			goto error;
	}

	if (xp_defaultuser(&auser, &akey) < 0)
		goto error;
	
	fs = xp_node_mount(nd, auser, akey);
	if (!fs) {
		fs = xp_node_mount(nd, NULL, akey);
		if (!fs)
			goto error;
	}

	fid = spc_open(fs, "pwent", Oread);
	if (!fid)
                goto error;

        buf = sp_malloc(sizeof(*buf) * bufsize);
        if (!buf)
                goto error;

	n = spc_read(fid, (u8 *) buf, bufsize-1, 0);
	if (n < 0)
		goto error;
        buf[bufsize] = '\0';
	spc_close(fid);
	spc_umount(fs);
	
	n = tokenize(buf, &toks);
	if (n < 0)
		goto error;
	free(buf);
	xauth_destroy(akey);
	*pwent = toks;
	return n;
error:
	if (fid)
		spc_close(fid);
	if (fs)
		spc_umount(fs);
	if (buf)
		free(buf);
	if (akey)
		xauth_destroy(akey);

        return -1;
}
