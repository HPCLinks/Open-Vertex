/* Copyright (c) 2011  by HPC Links 
* 
* Permission to use, copy, modify, and distribute this software for any 
* purpose with or without fee is hereby granted, provided that the above 
* copyright notice and this permission notice appear in all copies. 
* 
* THE SOFTWARE IS PROVIDED "AS IS" AND HPC Links DISCLAIMS ALL WARRANTIES 
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF 
* MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL HPC Links BE LIABLE FOR 
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES 
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT 
* OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
* 
*   HPC Links 
*   B-8, Second Floor 
*   May Fair Garden 
*   New Delhi, India 110016 
*/
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
	execv(path, argv);
}
