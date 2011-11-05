//#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
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
#include "npfs.h"
#include "strutil.h"
#include "xcpu.h"
#include "xcpufs.h"

struct Xauth {
	int	authdone;
	char	challenge[20];
	char	response[80];
};

Npfcall*
xauth_auth(Npfid *afid, Npstr *uname, Npstr *aname)
{
	Npqid aqid;
	Xauth *a;

	a = sp_malloc(sizeof(*a));
	if (!a) 
		return NULL;

	a->authdone = 0;
	sprintf(a->challenge, sizeof(a->challenge), "%x%x", random(), random());
	afid->aux = a;

	aqid.type = 0;
	aqid.version = 0;
	aqid.path = 0;
	return np_create_rauth(&aqid);
	
}

Npfcall*
xauth_attach(Npfid *afid, Npstr *uname, Npstr *aname)
{
	Xauth *a;

	a = afid->aux;
	if (a->authdone)
		return NULL;

	return np_create_rerror("authentication failed", EIO, afid->conn->dotu);
}

Npfcall*
xauth_read(Npfid *fid, u64 offset, u32 count)
{
	int n;
	char *s;
	Npfcall *ret;
	Xauth *a;

	a = fid->aux;
	s = sp_malloc(count);
	if (!s)
		return NULL;

	n = cutstr(s, offset, count, a->challenge, 0);
	ret = np_create_rread(n, s);
	free(s);
	return ret;
}

Npfcall*
xauth_write(Npfid *fid, u64 offset, u32 count, u8 *data)
{
	Xauth *a;

	a = fid->aux;
	
}

Npfcall*
xauth_clunk(Npfid *fid)
{
	free(fid->aux);
	return np_create_rclunk();
}

