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
#include "libxcpu.h"
#include "xcpuimpl.h"

static int Bufsize = 32768;

static int xp_file_copy(Xpcopy *c);
static void xp_file_notify(Spcfd *spcfd, void *a);

int
xp_file_create_from_file(Xpfile **xpf, Spcfsys *fs, char *name, char *path)
{
	int n;
	char *tn, *fn;
	struct stat st;
	DIR *d;
	struct dirent *de;
	Xpfile *f;

	if (stat(path, &st) < 0) {
		sp_uerror(errno);
		return -1;
	}

	f = sp_malloc(sizeof(*f));
	if (!f) 
		return -1;

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
	f->create = 1;
	f->buf = NULL;
	f->buflen = 0;
	f->bufsize = 0;
	f->next = NULL;
	f->fd = -1;
	f->fid = NULL;
	f->spcfd = NULL;
	f->pos = 0;

	if (S_ISDIR(st.st_mode)) {
		d = opendir(path);
		if (!d) {
			sp_uerror(errno);
			goto error;
		}

		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] == '.' && (de->d_name[1] == '.' || de->d_name[1] == '\0'))
				continue;

			fn = malloc(strlen(path) + strlen(de->d_name) + 2);
			tn = malloc(strlen(f->name) + strlen(de->d_name) + 2);
			if (!fn || !tn) {
				free(fn);
				free(tn);
				sp_werror(Enomem, ENOMEM);
				goto error;
			}

			sprintf(fn, "%s/%s", path, de->d_name);
			sprintf(tn, "%s/%s", f->name, de->d_name);
			n = xp_file_create_from_file(&f->next, fs, tn, fn);
			free(fn);
			free(tn);
			if (n < 0) 
				goto error;
		}
		closedir(d);
		d = NULL;
	}

	if (*xpf)
		while (*xpf != NULL)
			xpf = &(*xpf)->next;

	*xpf = f;

	return 0;

error:
	if (d)
		closedir(d);

	xp_file_destroy_all(f);
	return -1;
}

int
xp_file_create_from_buf(Xpfile **xpf, Spcfsys *fs, char *name, char *buf, int buflen)
{
	Xpfile *f;

	f = sp_malloc(sizeof(*f));
	if (!f)
		return -1;

	f->fs = fs;
	f->name = strdup(name);
	f->perm = 0;
	f->create = 0;
	f->path = NULL;
	f->buf = buf;
	f->buflen = buflen;
	f->bufsize = 0;
	f->next =NULL;
	f->fd = -1;
	f->fid = NULL;
	f->spcfd = NULL;
	f->pos = 0;

	if (*xpf)
		while (*xpf != NULL)
			xpf = &(*xpf)->next;

	*xpf = f;
	return 0;
}

void
xp_file_destroy(Xpfile *f)
{
	if (!f)
		return;

	if (f->spcfd)
		spcfd_remove(f->spcfd);
	if (f->fid)
		spc_close(f->fid);
	if (f->fd >= 0)
		close(f->fd);

	free(f->buf);
	free(f->name);
	free(f->path);
	free(f);
}

void
xp_file_destroy_all(Xpfile *f)
{
	Xpfile *ff, *ff1;

	ff = f;
	while (ff != NULL) {
		ff1 = ff->next;
		xp_file_destroy(ff);
		ff = ff1;
	}
}

Xpcopy *
xp_file_copy_start(Xpfile *files)
{
	Xpfile *f;
	Xpcopy *c;

	c = malloc(sizeof(*c));
	if (!c) {
		sp_werror(Enomem, ENOMEM);
		return NULL;
	}

	c->files = files;
	c->cfile = files;
	c->finish = NULL;
	c->finishaux = NULL;

	for(f = files; f != NULL; f = f->next) {
		int append = 0;
		if (strstr(f->name, "env"))
			append = Oappend;
		if (f->create) {
			f->fid = spc_create(f->fs, f->name, f->perm, Owrite | append);
			if (!f->fid && f->perm&Dmdir)
				f->fid = spc_open(f->fs, f->name, Oread);
		} else
			if (append)
				f->fid = spc_open(f->fs, f->name, Owrite | append);
			else
				f->fid = spc_open(f->fs, f->name, Owrite | Otrunc);


		if (!f->fid) {
			free(c);
			return NULL;
		}
	}

	xp_file_copy(c);
	return c;
}

int
xp_file_copy_finish(Xpcopy *c)
{
	Xpfile *f;

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
xp_file_copy(Xpcopy *c)
{
	Xpfile *f;

	for(f = c->cfile; f!=NULL && f->perm&Dmdir; f = f->next)
		;

	c->cfile = f;
	if (!f) {
		if (c->finish)
			(*c->finish)(c, c->finishaux);
		return 0;
	}

	f->spcfd = spcfd_add(f->fid, xp_file_notify, c, 0);
	if (!f->spcfd) {
		if (c->finish)
			(*c->finish)(c, c->finishaux);
		return -1;
	}

	xp_file_notify(f->spcfd, c);
	return 0;
}

static void
xp_file_notify(Spcfd *spcfd, void *a)
{
	int n, ecode;
	char *ename;
	Xpcopy *c;
	Xpfile *f;

	c = a;
	f = c->cfile;

error:
	if (sp_haserror()) {
		sp_rerror(&ename, &ecode);
		if (c->finish)
			(*c->finish)(c, c->finishaux);

//		spcfd_remove(spcfd);
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
	return;

next_file:
	spcfd_remove(f->spcfd);
	f->spcfd = NULL;
	c->cfile = f->next;
	xp_file_copy(c);
}
