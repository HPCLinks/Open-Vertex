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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include "spfs.h"
#include "spclient.h"
#include "xcpu.h"
#include "libxauth.h"
#include "xcpufs.h"

static int Bufsize = 32768;

struct Rxcopy {
	Rxfile*		files;
	Rxfile*		cfile;
	char*		ename;
	int		ecode;
	void		(*cb)(void *);
	void*		cba;
};

static int rxfile_copy(Rxcopy *c);
static void rxfile_notify(Spcfd *spcfd, void *a);

Rxfile *
rxfile_create_from_file(Spcfsys *fs, char *name, char *path)
{
	char *tn, *fn;
	struct stat st;
	DIR *d;
	struct dirent *de;
	Rxfile *f, *cf, *ff;

	f = sp_malloc(sizeof(*f));
	if (!f)
		return NULL;

	if (stat(path, &st) < 0) {
		sp_uerror(errno);
		free(f);
		return NULL;
	}

	f->perm = st.st_mode & 0777;
	if (S_ISDIR(st.st_mode))
		f->perm |= Dmdir;

	if (!name) {
		name = strrchr(path, '/');
		if (name)
			name++;
		else
			name = path;
	}

	f->fs = fs;
	f->name = strdup(name);
	f->path = strdup(path);
	if (!f->path || !f->name) {
		free(f->path);
		free(f->name);
		free(f);
		sp_werror(Enomem, ENOMEM);
		return NULL;
	}

	f->create = 1;
	f->buf = NULL;
	f->buflen = 0;
	f->next = NULL;
	f->fid = NULL;
	f->spcfd = NULL;
	f->pos = 0;
	f->fd = -1;

	if (S_ISDIR(st.st_mode)) {
		d = opendir(path);
		if (!d) {
			sp_uerror(errno);
			goto error;
		}

		cf = f;
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] == '.' && (de->d_name[1] == '.' || de->d_name[1] == '\0'))
				continue;

			fn = sp_malloc(strlen(path) + strlen(de->d_name) + 2);
			tn = sp_malloc(strlen(f->name) + strlen(de->d_name) + 2);
			if (!fn || !tn) {
				free(fn);
				free(tn);
				goto error;
			}

			sprintf(fn, "%s/%s", path, de->d_name);
			sprintf(tn, "%s/%s", f->name, de->d_name);
			ff = rxfile_create_from_file(fs, tn, fn);
			free(fn);
			free(tn);
			if (!ff) 
				goto error;

			cf->next = ff;
			for(cf = ff; cf->next != NULL; cf = f->next)
					;
		}
		closedir(d);
		d = NULL;
	}

	return f;

error:
	if (d)
		closedir(d);

	free(f->name);
	free(f->path);
	free(f);
	return NULL;
}

Rxfile *
rxfile_create_from_buf(Spcfsys *fs, char *name, char *buf, int buflen)
{
	Rxfile *f;

	f = sp_malloc(sizeof(*f));
	if (!f) {
		free(buf);
		return NULL;
	}

	f->fs = fs;
	f->name = strdup(name);
	if (!f->name) {
		free(f);
		sp_werror(Enomem, ENOMEM);
		return NULL;
	}

	f->perm = 0;
	f->create = 0;
	f->path = NULL;
	f->buf = buf;
	f->buflen = buflen;
	f->next =NULL;
	f->fid = NULL;
	f->spcfd = NULL;
	f->pos = 0;
	f->fd = -1;

	return f;
}

void
rxfile_destroy(Rxfile *f)
{
	if (!f)
		return;

	if (f->spcfd) {
		spcfd_remove(f->spcfd);
		f->spcfd = NULL;
	}

	if (f->fid) {
		spc_close(f->fid);
		f->fid = NULL;
	}

	if (f->fd >= 0) {
		close(f->fd);
		f->fd = -1;
	}

	free(f->buf);
	free(f->name);
	free(f->path);
	free(f);
}

void
rxfile_destroy_all(Rxfile *f)
{
	Rxfile *ff, *ff1;

	ff = f;
	while (ff != NULL) {
		ff1 = ff->next;
		rxfile_destroy(ff);
		ff = ff1;
	}
}

Rxcopy *
rxfile_copy_start(Rxfile *files, void (*cb)(void *), void *cba)
{
	Rxfile *f;
	Rxcopy *c;

	c = sp_malloc(sizeof(*c));
	if (!c)
		return NULL;

	c->files = files;
	c->ename = NULL;
	c->ecode = 0;
	c->cb = cb;
	c->cba = cba;

	for(f = files; f != NULL; f = f->next) {
		if (f->create) {
			f->fid = spc_create(f->fs, f->name, f->perm, Owrite);
			if (sp_haserror() && (f->perm & Dmdir)) {
				sp_werror(NULL, 0);
				f->fid = spc_open(f->fs, f->name, Oread);
			}
		} else
			f->fid = spc_open(f->fs, f->name, Owrite | Otrunc);

		if (!f->fid) {
			free(c);
			return NULL;
		}
	}

	for(f = files; f && (f->perm & Dmdir); f = f->next)
		;
	c->cfile = f;
	rxfile_copy(c);
	return c;
}

int
rxfile_copy_check(Rxcopy *c)
{
	if (c->ename) {
		sp_werror(c->ename, c->ecode);
		return 1;
	}

	return c->cfile == NULL;
}

int
rxfile_copy_finish(Rxcopy *c)
{
	Rxfile *f;

	for(f = c->files; f != NULL; f = f->next) {
		if (f->spcfd) {
			spcfd_remove(f->spcfd);
			f->spcfd = NULL;
		}

		if (f->fid) {
			spc_close(f->fid);
			f->fid = NULL;
		}

		if (f->path) {
			free(f->buf);
			f->buf = NULL;
		}
	}

	free(c);
	return 0;
}

static int
rxfile_copy(Rxcopy *c)
{
	Rxfile *f;

	f = c->cfile;
	if (!f) {
		(*c->cb)(c->cba);
		return 0;
	}

	f->spcfd = spcfd_add(f->fid, rxfile_notify, c, 0);
	rxfile_notify(f->spcfd, c);
	return 0;
}

static void
rxfile_notify(Spcfd *spcfd, void *a)
{
	int n, ecode;
	uid_t uid;
	gid_t gid;
	char *ename;
	Rxcopy *c;
	Rxfile *f;

	c = a;
	f = c->cfile;
	uid = geteuid();
	gid = getegid();
	seteuid(0);
	setegid(0);

error:
	sp_rerror(&ename, &ecode);
	if (ecode) {
		c->ename = strdup(ename);
		c->ecode = ecode;
		spcfd_remove(f->spcfd);
		f->spcfd = NULL;
		(*c->cb)(c->cba);
		sp_werror(NULL, 0);
		setegid(gid);
		seteuid(uid);
		return;
	}

	if (!spcfd_can_write(spcfd))
		return;

	if (f->pos >= f->buflen) {
		if (!f->path) 
			goto next_file;

		if (f->fd < 0) {
			f->fd = open(f->path, O_RDONLY);
			if (f->fd < 0) {
				sp_uerror(errno);
				goto error;
			}

			f->bufsize = Bufsize;
			f->buf = malloc(f->bufsize);
			if (!f->buf) {
				sp_werror(Enomem, ENOMEM);
				goto error;
			}
		}

		n = read(f->fd, f->buf, f->bufsize);
		if (n < 0) {
			sp_uerror(errno);
			goto error;
		}

		if (n == 0) {
			close(f->fd);
			f->fd = -1;
			free(f->buf);
			f->buf = NULL;
			f->buflen = 0;
			f->bufsize = 0;
			f->pos = 0;
			goto next_file;
		}

		f->buflen = n;
		f->pos = 0;
	}

	n = spcfd_write(spcfd, f->buf + f->pos, f->buflen - f->pos);
	if (n <= 0)
		goto error;

	f->pos += n;
	setegid(gid);
	seteuid(uid);
	return;

next_file:
	setegid(gid);
	seteuid(uid);
	spcfd_remove(f->spcfd);
	f->spcfd = NULL;
	for(f = f->next; f && (f->perm & Dmdir); f = f->next)
		;
	c->cfile = f;
	rxfile_copy(c);
}
