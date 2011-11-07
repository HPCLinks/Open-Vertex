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
xp_group_add(Xpnodeset *nds, char *adminkey, char *gname, gid_t gid)
{
	Xcmd *addcmd;
	Spstr *cmd;

	if (!nds)
		return -1;
	
	cmd = sp_malloc(sizeof(*cmd));
	cmd->len = 512;
	cmd->str = sp_malloc(cmd->len);
	snprintf(cmd->str, cmd->len, "group-add %s %d\n", gname, gid);
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

	xp_nodeerror_print("xp_group_add");
	return -1;
}

int
xp_group_del(Xpnodeset *nds, char *adminkey, char *gname)
{
	Xcmd *delcmd;
	Spstr *cmd;

	if (!nds)
		return -1;
	
	cmd = sp_malloc(sizeof(*cmd));
	cmd->len = 512;
	cmd->str = sp_malloc(cmd->len);
	snprintf(cmd->str, cmd->len, "group-del %s\n", gname);
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

	xp_nodeerror_print("xp_group_del");
	return -1;
}

int
xp_group_flush(Xpnodeset *nds, char *adminkey)
{
	Xcmd *flcmd;
	Spstr *cmd;

	if (!nds)
		return -1;

	cmd = sp_malloc(sizeof(*cmd));
	cmd->str = strdup("group-flush\n");
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

	xp_nodeerror_print("xp_group_flush");
	return -1;
}

int
xp_getgrent(Xpnode *nd, char *adminkey, char ***grent)
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
			return -1;
	}
	
	if (xp_defaultuser(&auser, &akey) < 0)
		goto error;
		
	fs = xp_node_mount(nd, auser, akey);
	if (!fs) {
		fs = xp_node_mount(nd, NULL, akey);
		if (!fs)
			goto error;
	}
	
	fid = spc_open(fs, "grent", Oread);
	if (!fid) {
		sp_werror("error opening file grent", EIO);
                goto error;
	}        
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
	*grent = toks;	
	return n;
error:
	if (akey)
		xauth_destroy(akey);
	if (fid)
		spc_close(fid);
	if (fs)
		spc_umount(fs);
	if (buf)
		free(buf);

	return -1;
}
