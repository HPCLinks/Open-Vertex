#include <stdio.h>
#include <string.h>

static char buf[SZ * 1024] = { 1, 2, 3 };

int
main()
{
	memset(buf, 42, sizeof(buf));
	return 0;
}
