#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spfs.h"
#include "libxauth.h"

int
main(int argc, char **argv)
{
	int n, siglen, ecode;
	char str[] = "This is a test";
	char buf[1024], sig[1024];
	char *home, *ename;
	Xkey *pvkey, *pukey;

	home = getenv("HOME");
	snprintf(buf, sizeof(buf), "%s/.ssh/id_rsa", home);
	pvkey = xauth_privkey_create(buf);
	if (!pvkey)
		goto error;

	snprintf(buf, sizeof(buf), "%s/.ssh/id_rsa.pub", home);
	pukey = xauth_pubkey_create_from_file(buf);
	if (!pukey)
		goto error;

	siglen = xauth_sign(str, strlen(str), sig, sizeof(sig), pvkey);
	if (siglen < 0)
		goto error;

	n = xauth_verify(str, strlen(str), sig, siglen, pukey);
	fprintf(stderr, "%d\n", n);
	return 0;

error:
	sp_rerror(&ename, &ecode);
	fprintf(stderr, "Error: %s\n", ename);
	return -1;
}
