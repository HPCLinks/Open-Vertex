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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "spfs.h"
#include "spclient.h"
#include "spcimpl.h"

/* this should be at least 3 functions. parse an address into 
  * sockaddr. make a socket. Mount a given sockaddr. This needs
  * rewriting. 
  * oh, hell, let's just do it.
  */

/* parse an address in plan 9 format into a sockaddr
  * NOT a sockaddr_in yet if ever.
  * if you want defaults, then put them in the string!
  */
struct sockaddr *parse9net(const char *address, struct sockaddr *psaddr)
{
	int port;
	char *addr, *name, *p, *s;
	struct sockaddr_in *saddr = (struct sockaddr_in *)psaddr;
	struct hostent *hostinfo;

	addr = strdup(address);
	if (strncmp(addr, "tcp!", 4) == 0)
		name = addr + 4;
	else
		name = addr;

	port = 0;
	p = strrchr(name, '!');
	if (p) {
		*p = '\0';
		p++;
		port = strtoul(p, &s, 0);
		if (*s != '\0') {
			sp_werror("invalid port format", EIO);
			goto error;
		}
	}

	hostinfo = gethostbyname(name);
	if (!hostinfo) {
		sp_werror("cannot resolve name: %s", EIO, name);
		goto error;
	}

	free(addr);

	saddr->sin_family = AF_INET;
	saddr->sin_port = htons(port);
	saddr->sin_addr = *(struct in_addr *) hostinfo->h_addr;

	return (struct sockaddr *) saddr;

error:
	return NULL;
}

Spcfsys *
spc_netmount(char *address, Spuser *user, int dfltport, 
	int (*auth)(Spcfid *afid, Spuser *user, void *aux), void *aux)
{
	int fd, port;
	socklen_t n;
	char *addr, *name, *p, *s;
	struct sockaddr_in saddr;
	struct hostent *hostinfo;
	unsigned char a[4];
	char buf[64];
	Spcfsys *fs;

	addr = strdup(address);
	if (strncmp(addr, "tcp!", 4) == 0)
		name = addr + 4;
	else
		name = addr;

	port = dfltport;
	p = strrchr(name, '!');
	if (p) {
		*p = '\0';
		p++;
		port = strtol(p, &s, 10);
		if (*s != '\0') {
			sp_werror("invalid port format", EIO);
			goto error;
		}
	}

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		sp_uerror(errno);
		goto error;
	}

	hostinfo = gethostbyname(name);
	if (!hostinfo) {
		sp_werror("cannot resolve name: %s", EIO, name);
		goto error;
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr = *(struct in_addr *) hostinfo->h_addr;

	if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		/* real computers have errstr */
		static char error[128];
		/* too bad for f-ing gcc and friends */
		a[0] = saddr.sin_addr.s_addr >> 24;
		a[1] = saddr.sin_addr.s_addr >>16;
		a[2] = saddr.sin_addr.s_addr >>8;
		a[3] = saddr.sin_addr.s_addr;
		/* yeah, they broke this too
		char *i = inet_ntoa(saddr.sin_addr);
 		 */
		
		memset(error, 0, sizeof(error));
		//strerror_r(errno, error, sizeof(error));
		strcpy(error, strerror(errno));
		error[strlen(error)] = ':';
		sprintf(&error[strlen(error)], "%d.%d.%d.%d", a[3], a[2], a[1], a[0]);
//		sp_werror("Host :%s:%s", errno, i, error);
		sp_werror(error, errno);
		goto error;
	}

	free(addr);
	addr = NULL;
	fs = spc_mount(fd, NULL, user, auth, aux);
	if (!fs)
		goto error;

	n = sizeof(saddr);
	if (getsockname(fd, (struct sockaddr *) &saddr, &n) >= 0) {
		a[0] = saddr.sin_addr.s_addr >> 24;
		a[1] = saddr.sin_addr.s_addr >> 16;
		a[2] = saddr.sin_addr.s_addr >> 8;
		a[3] = saddr.sin_addr.s_addr;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", a[3], a[2], a[1], a[0]);
		fs->laddr = strdup(buf);
	}

	n = sizeof(saddr);
	if (getpeername(fd, (struct sockaddr *) &saddr, &n) >= 0) {
		a[0] = saddr.sin_addr.s_addr >> 24;
		a[1] = saddr.sin_addr.s_addr >> 16;
		a[2] = saddr.sin_addr.s_addr >> 8;
		a[3] = saddr.sin_addr.s_addr;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", a[3], a[2], a[1], a[0]);
		fs->raddr = strdup(buf);
	}

	if (spc_chatty)
		fprintf(stderr, "connection %p to %s opened\n", fs, fs->raddr);

	return fs;

error:
	free(addr);
	return NULL;
}
