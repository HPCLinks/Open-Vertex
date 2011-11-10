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

typedef struct Spcfid Spcfid;
typedef struct Spcfsys Spcfsys;
typedef struct Spcfd Spcfd;

struct Spcfsys;
struct Spcfd;

struct Spcfd {
	Spfd*		spfd;
	Spcfid*		fid;
	int		flags;
	int		iounit;
	void		(*notify)(Spcfd *, void *);
	void*		aux;
	u64		offset;
	u8*		rbuf;
	int		rpos;
	u8*		wbuf;
	int		wpos;
	Spfcall*	rtc;
	Spfcall*	wtc;

	Spcfd*		next;
};

struct Spcfid {
	u32		iounit;
	u8		mode;
	Spcfsys*	fsys;
	u32		fid;
	u64		offset;
};

extern int spc_chatty;
extern int spc_msize;

Spcfsys* spc_mount(int fd, char *aname, Spuser *user,
	int (*auth)(Spcfid *afid, Spuser *user, void *aux), void *aux);
void spc_remount(Spcfsys *);
void spc_umount(Spcfsys *fs);
Spcfsys * spc_netmount(char *address, Spuser *user, int dfltport,
	int (*auth)(Spcfid *afid, Spuser *user, void *aux), void *aux);
Spcfid* spc_create(Spcfsys *fs, char *path, u32 perm, int mode);
Spcfid* spc_open(Spcfsys *fs, char *path, int mode);
int spc_close(Spcfid *fid);
int spc_remove(Spcfsys *fs, char *path);
int spc_read(Spcfid *fid, u8 *buf, u32 count, u64 offset);
int spc_write(Spcfid *fid, u8 *buf, u32 count, u64 offset);
int spc_dirread(Spcfid *fid, Spwstat **stat);
Spwstat *spc_stat(Spcfsys *fs, char *path);
int spc_wstat(Spcfsys *fs, char *path, Spwstat *wst);
int spc_readnb(Spcfid *fid, u8 *buf, u32 count, u64 offset,
	void (*cb)(void *, int), void *cba);
int spc_writenb(Spcfid *fid, u8 *buf, u32 count, u64 offset,
	void (*cb)(void *, int), void *cba);
Spcfd *spcfd_add(Spcfid *fid, void (*notify)(Spcfd *, void *), void *aux,
	u64 offset);
Spcfd *spcfd_add_fd(int fd, void (*notify)(Spcfd *, void *), void *aux);
void spcfd_remove(Spcfd *spcfd);
int spcfd_can_write(Spcfd *spcfd);
int spcfd_can_read(Spcfd *spcfd);
int spcfd_has_error(Spcfd *spcfd);
int spcfd_done_writing(Spcfd *spcfd);
void spcfd_start_loop(void);
void spcfd_stop_loop(void);
int spcfd_read(Spcfd *spcfd, void *buf, int buflen);
int spcfd_write(Spcfd *spcfd, void *buf, int buflen);

int spc_getladdr(Spcfsys *fs, char *buf, int buflen);
int spc_getraddr(Spcfsys *fs, char *buf, int buflen);
