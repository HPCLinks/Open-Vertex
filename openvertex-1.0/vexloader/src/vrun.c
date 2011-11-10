#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

main(int argc, char* argv[])
{
	char path[256];
	char* str = getenv("VEXHOME");
	strcpy(path, str);
	strcat(path, "/bin/vex_loader");
	printf("%s\n", path);
	execv(path, argv);
}
