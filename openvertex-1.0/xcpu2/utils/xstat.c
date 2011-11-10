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

#include "spfs.h"
#include "spclient.h"
#include "strutil.h"
#include "libxauth.h"
#include "libxcpu.h"
#include "xcpu.h"

extern int spc_chatty;

static char defserver[32];

static char *ename;
static int ecode;

void 
usage(char *argv) 
{
	fprintf(stderr, "usage: %s [-d] [-s server] [nodes]\n", argv);
	exit(1);
}

int
main(int argc, char **argv)
{
	Xpnodeset *ns, *uns = xp_nodeset_create();
	char *nodelist = NULL;
	char *server = NULL, *str = NULL;
	int c;

	while ((c = getopt(argc, argv, "ds:")) != -1) {
		switch (c) {
		case 'd':
			spc_chatty = 1;
			break;
		case 's':
			server = strdup(optarg);
			break;
		default:
			usage(argv[0]);
		}
	}

	if (optind < argc)
		nodelist = argv[optind++];

	if (optind != argc)
		usage(argv[0]);

	ns = xp_nodeset_list(server);
	if(ns == NULL && server == NULL){
		sprintf(defserver, "localhost!%d", STAT_PORT);
		ns = xp_nodeset_list(defserver);
	}

	if(ns == NULL) {
			sp_rerror(&ename, &ecode);
			fprintf(stderr, "Error: could not obtain node list from statfs: %s: %d\n", ename, ecode);
			return 1;
	}

	if(nodelist) {
		if(xp_nodeset_filter_by_node(uns, ns, nodelist) < 0)
			goto error;	/* assume libxcpu set proper error */
	} else 
		uns = ns;

	str = xp_nodeset_to_string(uns);
	if(str != NULL)
		printf("%s", str);
	else {
		fprintf(stderr, "bad string from xp_nodeset_to_string(): ");
		goto error;
	} 
	return 0;

error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "Error: %s: %d\n", ename, ecode);

	return 1;
}
