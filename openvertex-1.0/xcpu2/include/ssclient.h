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

struct Spcfsys;
struct Spcfd;

struct Spcfid {
	u32		iounit;
	Spcfsys*	fsys;
	u32		fid;
	u64		offset;
};

Spcfsys* spc_mount(int fd, char *aname, char *uname, u32 n_uname);
void spc_remount(Spcfsys *);
void spc_umount(Spcfsys *fs);
Spcfsys * spc_netmount(char *address, char *uname, int dfltport);
Spcfid* spc_create(Spcfsys *fs, char *path, u32 perm, int mode);
Spcfid* spc_open(Spcfsys *fs, char *path, int mode);
int spc_close(Spcfid *fid);
int spc_remove(Spcfsys *fs, char *path);
int spc_read(Spcfid *fid, u8 *buf, u32 count, u64 offset);
int spc_write(Spcfid *fid, u8 *buf, u32 count, u64 offset);
int spc_dirread(Spcfid *fid, Spwstat **stat);
Spwstat *spc_stat(Spcfsys *fs, char *path);
