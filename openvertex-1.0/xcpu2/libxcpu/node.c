/*
 * Copyright (C) 2006 by Latchesar Ionkov <lucho@ionkov.net>
 * Copyright (C) 2006 by Andrey Mirtchovski <andrey@lanl.gov>
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
#include <signal.h>
#include <dirent.h>
#include <signal.h>
#include <regex.h>
#include <math.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netdb.h>

#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "xcpu.h"
#include "libxauth.h"
#include "libxcpu.h"
#include "xcpuimpl.h"

static Xpnodeerror *errorpool = NULL;

Xpnode *
xp_node_create(char *name, char *addr, char *arch, char *status, int numjobs)
{
	Xpnode *nd;

	nd = sp_malloc(sizeof(*nd));
	if (!nd)
		return NULL;

	if (name)
		nd->name = strdup(name);
	else
		nd->name = NULL;

	if (addr)
		nd->addr = strdup(addr);
	else
		nd->addr = NULL;

	if (arch)
		nd->arch = strdup(arch);
	else
		nd->arch = NULL;

	if (status)
		nd->status = strdup(status);
	else
		nd->status = NULL;

	nd->numjobs = numjobs;

	return nd;
}

void
xp_node_destroy(Xpnode *nd)
{
	free(nd->name);
	free(nd->addr);
	free(nd->arch);
	free(nd->status);
	free(nd);
}

Xpnodeset *
xp_nodeset_create(void)
{
	Xpnodeset *nds;

	nds = sp_malloc(sizeof(*nds));
	if (!nds)
		return NULL;

	nds->size = 0;
	nds->len = 0;
	nds->nodes = NULL;

	return nds;
}

void
xp_nodeset_destroy(Xpnodeset *nds)
{
	int i;
	Xpnode *nd;

	for(i = 0; i < nds->len; i++) {
		nd = &nds->nodes[i];
		free(nd->name);
		free(nd->addr);
		free(nd->arch);
		free(nd->status);
	}

	free(nds->nodes);
	free(nds);
}

static int
xp_nodeerror_add(Xpnode *nd, char *ename, int ecode) 
{
	Xpnodeerror *nderr;
	
	nderr = sp_malloc(sizeof(*nderr));
	if(!nderr)
		return -1;
	
	nderr->node = nd;
	if (ename)
		nderr->ename = strdup(ename);
	else
		nderr->ename = NULL;

	nderr->ecode = ecode;
	nderr->next = errorpool;
	errorpool = nderr;
	
	return 0;
}

void 
xp_nodeerror_print(char *prog)
{
	Xpnodeerror *ne = NULL, *pe = NULL;	
	for(pe = NULL, ne = errorpool; ne != NULL; pe = ne, ne = ne->next) {
		fprintf(stderr, "%s: %s: Error %d: %s\n",
			prog, ne->node->name, ne->ecode, ne->ename);

		errorpool = ne->next;
		if (pe) {
                        free(pe->ename);
                        free(pe);
                }
	}
	if (pe) {
                free(pe->ename);
                free(pe);
        }
}

/*
static int
xp_node_get_arch(Spuser *u, char *name, char *buf, int buflen)
{
	int n;
	Spcfsys *fs;
	Spcfid *fid;

	fs = spc_netmount(name, u->uname, u->uid, XCPU_PORT);
	if (!fs)
		return -1;

	fid = spc_open(fs, "arch", Oread);
	if (!fid) {
		spc_umount(fs);
		return -1;
	}

	n = spc_read(fid, (u8 *) buf, buflen - 1, 0);
	spc_close(fid);
	spc_umount(fs);

	if (n > 0)
	       buf[n] = '\0';

	return n>0?0:-1;
}

*/

static char *
xp_node_create_from_buf(Xpnode **node, char *buf)
{
	char *addr, *arch, *status, *eol, *numjobs;
	
	addr = strchr(buf, '\t');
	if(addr == NULL) {
		sp_werror("Bad format in statfs: address", EIO);
		return NULL;
	}
	*addr++ = '\0';

	arch = strchr(addr, '\t');
	if(arch == NULL) {
		sp_werror("Bad format in statfs: architecture", EIO);
		return NULL;
	}
	*arch++ = '\0';

	status = strchr(arch, '\t');
	if(status == NULL) {
		sp_werror("Bad format in statfs: status", EIO);
		return NULL;
	}
	*status++ = '\0';
	numjobs = strchr(status, '\t');
	if(numjobs == NULL) {
		sp_werror("Bad format in statfs: numjobs", EIO);
		return NULL;
	}
	*numjobs++ = '\0';
	eol = strchr(numjobs, '\n');
	if(eol) {
		*eol++ = '\0';
	} 

	*node = xp_node_create(buf, addr, arch, status, strtoul(numjobs, 0, 0));
	if(*node == NULL) {
		sp_werror("Error creating node", ENOMEM);
		return NULL;
	}
	buf = eol;
	return buf;
}

static int
xp_nodeset_create_node(Xpnodeset *nds, char *name)
{
	Xpnode *nd;

	nd = xp_node_create(name, name, NULL, NULL, 0);
	xp_nodeset_add(nds, nd);
	return 0;
}

static int
xp_nodeset_parse_noderange(Xpnodeset *nds, char *noderange)
{
	int i, n;
	char *s, **nodes = NULL;

	/* we allow two kinds of description here -- abcd123 and abcd[2-56] */
	s = noderange;
	n = parse_range(noderange, &nodes);
	if (n < 0)
		goto error;
	else if (n == 1) {	/* Not a range */
		s = nodes[0];
		while (isalpha(*s))
			s++;

		if (isdigit(*s) || *s == '\0' || *s == '!') {
			while (isdigit(*s) || *s == '.' || *s == '-' || isalpha(*s))
				s++;
			
			if (*s == '!') {
				s++;
				while (isdigit(*s))
					s++;
			}
			
			if (*s != '\0')
				goto error;			
		}
	}

	for (i = 0; i < n; i++) {
		if (xp_nodeset_create_node(nds, nodes[i]) < 0)
			goto error;
	}
	free(nodes);
	return 0;

error:
	free(nodes);
	sp_werror("syntax error: '%s' not a valid node description", EIO, noderange);
	return -1;
}

static int
xp_nodeset_parse_nodelist(Xpnodeset *nds, char *nodelist)
{
	int ret;
	char *nlist, *s, *p;

	ret = -1;
	nlist = strdup(nodelist);
	if (!nlist) {
		sp_werror(Enomem, ENOMEM);
		return -1;
	}
	
	s = nlist;
	while ((p = strchr(s, ',')) != NULL) {
		*p = '\0';
		if (strlen(s)>0 && xp_nodeset_parse_noderange(nds, s) < 0)
			goto done;

		s = p + 1;
	}

	if (*s != '\0' && xp_nodeset_parse_noderange(nds, s) < 0)
		goto done;

	ret = 0;
done:
	free(nlist);
	return ret;
}

static void
xp_node_get_addr(Xpnode *nd)
{
	char buf[64], *name;
	unsigned char *s;
	struct hostent *hostinfo;
	struct in_addr *iaddr;

	name = strdup(nd->name);
	if ((s = strchr(name, '!')) != NULL)
		*s = '\0';

	free(name);
	hostinfo = gethostbyname(nd->name);
	if (!hostinfo) 
		return;

	iaddr = (struct in_addr *) hostinfo->h_addr;
	s = (char *)&iaddr->s_addr;
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", s[0], s[1], s[2], s[3]);
	free(nd->addr);
	nd->addr = strdup(buf);
}

Xpnodeset *
xp_nodeset_from_string(char *nodelist)
{
	Xpnodeset *nds;
	int i;

	nds = xp_nodeset_create();
	if (!nds)
		return NULL;

	if (xp_nodeset_parse_nodelist(nds, nodelist) < 0) {
		xp_nodeset_destroy(nds);
		return NULL;
	}

	for(i = 0; i < nds->len; i++) {
		xp_node_get_addr(&nds->nodes[i]);
//		if (xp_node_get_arch(nds->nodes[i].name, buf, sizeof(buf)) == 0)
//			nds->nodes[i].arch = strdup(buf);
	}

	return nds;
}

char *
xp_node_to_string(Xpnode *n)
{
	char *ret;
	int len;

	if(n == NULL) {
		sp_werror("Bad node in xp_node_to_str", EIO);
		return NULL;
	}

	if(n->name == NULL || n->addr == NULL || n->arch == NULL || n->status == NULL || (n->numjobs < 0)) {
		sp_werror("Bad value in xp_node_to_str", EIO);
		return NULL;
	}

	/* count whitespace in */
	len = strlen(n->name) + 1; 
	len += strlen(n->addr) + 1; 
	len += strlen(n->arch) + 1; 
	len += strlen(n->status) + 1; 
	/* let's assume less than 10 digits of numjobs */
	len += 9 + 2; 

	ret = sp_malloc(len*sizeof(char)); 
	if(ret == NULL) { 
		sp_werror(Enomem, ENOMEM);
		return NULL;
	}

	sprintf(ret, "%s\t%s\t%s\t%s\t%d\n", n->name, n->addr, n->arch, n->status, n->numjobs);
	return ret;
}

char *
xp_nodeset_to_string(Xpnodeset *ns)
{
	char *ret = NULL, *rea = NULL, *str;
	int i, total;

	if(ns == NULL) {
		sp_werror("Null nodeset in xp_nodeset_to_string", EIO);
		return NULL;
	}

	for(i = 0; i < ns->len; i++) {
		str = xp_node_to_string(&ns->nodes[i]);
		if(str == NULL)
			goto xp_nodeset_to_string_error;

		if(ret == NULL) {
			/* take more memory than we need, we'll free it later */
			total = strlen(str)*ns->len*2;
			ret = malloc(total*sizeof(char));
			if(ret == NULL)
				goto xp_nodeset_to_string_error;
			strcpy(ret, str); 
		} else if((strlen(str) + strlen(ret)) > total) {
			/* the realloc dance: if realloc fails the previous pointer is still
			 * valid and must be freed before exit
			 */
			rea = realloc(ret, (strlen(ret)+strlen(str))*sizeof(char));
			if(rea == NULL)
				goto xp_nodeset_to_string_error;
			ret = rea;

			strcat(ret, str);
			total += strlen(str);
		} else {
			strcat(ret, str);
		}
		free(str);
	}

	return ret;

xp_nodeset_to_string_error:
	if(ret)
		free(ret);
	if(str)
		free(str);
	return NULL;
}

static int
xp_nodeset_add_nodes(Xpnodeset *nds, int nnodes, Xpnode *nodes)
{
	int i, n;
	Xpnode *tmp;

	if (nds->size-nds->len < nnodes) {
		n = nnodes+nds->len;
		n += n%32?32-n%32:0;
		tmp = realloc(nds->nodes, n * sizeof(Xpnode));
		if (!tmp) {
			sp_werror(Enomem, ENOMEM);
			return -1;
		}

		nds->nodes = tmp;
		nds->size = n;
	}

	for(i = 0; i < nnodes; i++)
		nds->nodes[nds->len + i] = nodes[i];

	nds->len += nnodes;
	return 0;
}

int
xp_nodeset_add(Xpnodeset *nds, Xpnode *nd)
{
	return xp_nodeset_add_nodes(nds, 1, nd);
}

int
xp_nodeset_append(Xpnodeset *to, Xpnodeset *from)
{
	return xp_nodeset_add_nodes(to, from->len, from->nodes);
}

int
xp_nodeset_filter_by_node(Xpnodeset *out, Xpnodeset *in, char *nodelist)
{
	int i, j;
	Xpnodeset *nds;

	nds = xp_nodeset_create();
	if (!nds)
		return -1;

	if (xp_nodeset_parse_nodelist(nds, nodelist) < 0) {
		xp_nodeset_destroy(nds);
		return -1;
	}

	for(i = 0; i < in->len; i++)
		for(j = 0; j < nds->len; j++)
			if (strcmp(in->nodes[i].name, nds->nodes[j].name) == 0)
				xp_nodeset_add(out, &in->nodes[i]);

	xp_nodeset_destroy(nds);
	return 0;
}

int
xp_nodeset_filter_by_state(Xpnodeset *out, Xpnodeset *in, char *state)
{
	int i;

	for(i = 0; i < in->len; i++) 
		if (strcmp(in->nodes[i].status, state) == 0)
			xp_nodeset_add(out, &in->nodes[i]);

	return 0;
}

int
xp_nodeset_iterate(Xpnodeset *nds, int (*itcb)(Xpnode *, void *), void *cba)
{
	int i, ret, ecode;
	int count = 0;
	char *ename;

	for(i = 0; i < nds->len; i++) {
		if ((*itcb)(&nds->nodes[i], cba) < 0) {
			sp_rerror(&ename, &ecode);
			if (ename)
				ename = strdup(ename);
			ret = xp_nodeerror_add(&nds->nodes[i], ename, ecode);
			if(ret < 0)
				return -1;
			count++;
		}
	}
	
	return count;
}

Xpnodeset *
xp_nodeset_listnet_filter(char *server, char *state, char *arch, int minjobs,
			      int maxjobs)
{
	Spcfsys *fs = NULL;
	Spcfid *fid = NULL;
	Xpnodeset *ns = NULL;
	Xpnode *node = NULL;
	char *buf = NULL, *name;
	Spuser *user;
	int n, bufsize, pos;
	int add = 1;

	if (!server)
		return NULL;

	user = sp_unix_users->uid2user(sp_unix_users, geteuid());
	if (!user)
		goto error;

	fs = spc_netmount(server, user, STAT_PORT, NULL, NULL);
	if (!fs)
		return NULL;

	fid = spc_open(fs, "/state", Oread);
	if (!fid) {
		sp_werror("Can not open statfs", EIO);
		goto error;
	}

	ns = xp_nodeset_create();
	if(!ns)
		goto error;

	bufsize = fid->iounit;
	buf = sp_malloc(fid->iounit + 1);
	pos = 0;
	while ((n = spc_read(fid, (u8 *) buf, fid->iounit - 1, pos)) > 0) {
		pos += n;
		if (bufsize-pos < fid->iounit) {
			bufsize += fid->iounit;
			buf = realloc(buf, bufsize);
			if (!buf) {
				sp_uerror(ENOMEM);
				goto error;
			}
		}
	}

	if (n < 0)
		goto error;

	buf[pos] = '\0';
	name = buf;

	while(strcmp(name, "")) {
		name = xp_node_create_from_buf(&node, name);
		if (!name)
			goto error;

		add = 1;
		if (state)
			add &= (!strcmp(node->status, state));		
		if (arch)
			add &= (!strcmp(node->arch, arch));
		if (minjobs >= 0)
			add &= (node->numjobs >= minjobs);			
		if (maxjobs >= 0)
			add &= (node->numjobs <= maxjobs);

		if (add)
			xp_nodeset_add(ns, node);
	}

	free(buf);
	spc_close(fid);
	spc_umount(fs);
	return ns;

error:
	if(fid)
		spc_close(fid);
	if(fs)
		spc_umount(fs);
	free(buf);

	if(ns)
		xp_nodeset_destroy(ns);

	return NULL;
}

Xpnodeset *
xp_nodeset_list_filter(char *server, char *state, char *arch, int minjobs,
		       int maxjobs)
{
	int add;
	Xpnodeset *ns = NULL;
	Xpnode *n = NULL;
	FILE *f;
	char buf[512], *name;

	if (server)
		return xp_nodeset_listnet_filter(server, state, arch, minjobs, 
						 maxjobs);

	f = fopen("/mnt/statfs/state", "r");
	if(f == NULL) {
		sp_uerror(errno);
		goto nodeset_list_err;
	}

	ns = xp_nodeset_create();
	if(ns == NULL) {
		sp_werror(Enomem, ENOMEM);
		goto nodeset_list_err;
	}

	while(fgets(buf, 511, f) != NULL) {
		if(buf[strlen(buf)-1] == '\n')
			buf[strlen(buf)-1] = '\0';

		name = buf;		
		name = xp_node_create_from_buf(&n, name);
		if (!name)
			goto nodeset_list_err;
		
		add = 1;
		if (state)
			add &= (!strcmp(n->status, state));		
		if (arch)
			add &= (!strcmp(n->arch, arch));
		if (minjobs >= 0)
			add &= (n->numjobs >= minjobs);		       
		if (maxjobs >= 0)
			add &= (n->numjobs <= maxjobs);

		if (add)
			xp_nodeset_add(ns, n);
	}
			
	fclose(f);

	return ns;

nodeset_list_err:
	if(f)
		fclose(f);
	if(ns)
		xp_nodeset_destroy(ns);
	return NULL;
}

Xpnodeset *
xp_nodeset_listfromnet(char *server)
{
	if (!server)
		return NULL;

	return xp_nodeset_listnet_filter(server, NULL, NULL, -1, -1);
}

Xpnodeset *
xp_nodeset_list(char *server)
{
	/* if server is given use that */
	if(server)
		return xp_nodeset_listfromnet(server);
	
	return xp_nodeset_list_filter(server, NULL, NULL, -1, -1);
}

Xpnodeset *
xp_nodeset_list_by_state(char *server, char *state)
{
	if (!state)
		return xp_nodeset_list(server);

	return xp_nodeset_list_filter(server, state, NULL, -1, -1);
}

Xpnodeset *
xp_nodeset_list_by_arch(char *server, char *arch)
{
	if (!arch)
		return xp_nodeset_list(server);

	return xp_nodeset_list_filter(server, NULL, arch, -1, -1);
}

Xpnodeset *
xp_nodeset_list_by_min_jobs(char *server, int minjobs)
{
	if (minjobs == 0)
		return xp_nodeset_list(server);

	return xp_nodeset_list_filter(server, NULL, NULL, minjobs, -1);
}

Xpnodeset *
xp_nodeset_list_by_max_jobs(char *server, int maxjobs)
{
	return xp_nodeset_list_filter(server, NULL, NULL, -1, maxjobs);
}

/*
static int
xp_node_cmp_arch(const void *a1, const void *a2)
{
	const Xpnode *n1, *n2;

	n1 = a1;
	n2 = a2;

	if (n1->arch && !n2->arch)
		return 1;
	else if (!n1->arch && n2->arch)
		return -1;
	else if (!n1->arch && !n2->arch)
		return 0;
	else
		return strcmp(n1->arch, n2->arch);
}

int
xp_nodeset_split_by_arch(Spuser *u, Xpnodeset *nds, Xpnodeset ***ndsa)
{
	int i, n, ecode;
	char *arch, *ename, buf[128];
	Xpnodeset **ret;

	if (nds->len == 0) {
		sp_werror("no nodes", EIO);
		return -1;
	}

	for(i = 0; i < nds->len; i++)
		if (!nds->nodes[i].arch) {
			if (xp_node_get_arch(u, nds->nodes[i].name, buf, sizeof(buf)) == 0)
				nds->nodes[i].arch = strdup(buf);
			else {
				sp_rerror(&ename, &ecode);
				if (ename)
					ename = strdup(ename);
				sp_werror("unknown architecture for %s: %s", 
					EIO, nds->nodes[i].name, ename?ename:"");
				free(ename);
				return -1;
			}
		}

	qsort(nds->nodes, nds->len, sizeof(Xpnode), &xp_node_cmp_arch);
	arch = NULL;
	for(n = 0, i = 0; i < nds->len; i++) {
		if (!arch || strcmp(nds->nodes[i].arch, arch) != 0) {
			arch = nds->nodes[i].arch;
			n++;
		}
	}

	ret = sp_malloc(n * sizeof(Xpnodeset *));
	if (!ret)
		return -1;

	memset(ret, 0, n * sizeof(Xpnodeset *));
	arch = NULL;
	for(n = -1, i = 0; i < nds->len; i++) {
		if (!arch || strcmp(nds->nodes[i].arch, arch) != 0) {
			arch = nds->nodes[i].arch;
			n++;
			ret[n] = xp_nodeset_create();
			if (!ret[n])
				goto error;
		}

		if (xp_nodeset_add(ret[n], &nds->nodes[i]) < 0)
			goto error;
	}

	*ndsa = ret;
	return n+1;

error:
	for(i = 0; i < n; i++)
		xp_nodeset_destroy(ret[i]);

	return -1;
}
*/
