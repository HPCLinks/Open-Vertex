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
*   New Delhi, India 110016 */

/*********************************************************************
   Usage:  

   // reserve 1 GPP resource for the given pid
   vex_client -q <process_identifier>

   // reserve a given number and type of resources for a given pid
   vex_client -r <num_gpp> <process_identifier>
   vex_client -r <num_gpp>:<num_gpu> <process_identifier>

   // make node busy i.e. make it unavailable for resource allocation
   vex_client -b node:<node_name>

   // free-up node i.e. make it available 
   vex_client -f node:<node_name>

   // free-up resources reserved earlier for the given pid
   vex_client -f pid:<process_identifier>

   // shows the list of all PIDs currently using resources otherwise returns nothing
   vex_client -l

   // shows the status of all NODES
   vex_client -n

***********************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/vex_hsched"
#define MAXSOCKBUFSZ 4096

int  vex_reserve(int argc, char* input[]);
int  vex_free(int argc, char* input[]);
int  vex_list(int argc, char* input[]);
int vex_usage(char* input[]);

char vex_sockbuf[MAXSOCKBUFSZ];

int main(int argc, char* argv[])
{
	int num_args = argc;
	char c;
	if (num_args > 1 && (*argv[1]) == '-')
	{
		c = (*(argv[1]+1));
		switch(c)
		{
			case 'b':
				vex_reserve(argc, argv);
				break;
			case 'r':
				vex_reserve(argc, argv);
				break;
			case 'q':
				vex_reserve(argc, argv);
				break;
			case 'f':
				vex_free(argc, argv);
				break;
			case 'l':
				vex_list(argc, argv);
				break;
			case 'n':
				vex_list(argc, argv);
				break;
			case 'h':
				vex_usage(argv);
				break;
			default:
				vex_usage(argv);
				break;	
		}
	}
	return 0;
}

int vex_reserve(int argc, char* input[])
{
	int sock_d, len;
	int recd_bytes;
	int success = 0;
	struct sockaddr_un remote;
  if ((sock_d = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
    perror("socket");
    exit(1);
  }
  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, SOCKET_PATH);
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(sock_d, (struct sockaddr *)&remote, len) == -1)
	{
    perror("connect");
    printf("Check if vex_hsched deamon is running:  vex_hsched -d <config>\n");
    exit(1);
  }
	
	strcpy(vex_sockbuf, input[1]);
	int i = 2;
	for (i = 2; i < argc; ++i)
	{
		strcat(vex_sockbuf, " ");
		strcat(vex_sockbuf, input[i]);
	}

  if (send(sock_d, vex_sockbuf, strlen(vex_sockbuf), 0) == -1)
	{
    perror("send");
    exit(1);
 	}
  if ((recd_bytes = recv(sock_d, vex_sockbuf, MAXSOCKBUFSZ, 0)) > 0)
	{
    vex_sockbuf[recd_bytes] = '\0';
    printf("%s", vex_sockbuf);
		success = 1;
 	}
 	close(sock_d);
	return success;
}

int vex_free(int argc, char* input[])
{
	int sock_d, len;
	int recd_bytes;
	int success = 0;
	struct sockaddr_un remote;
  if ((sock_d = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
    perror("socket");
    exit(1);
  }
  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, SOCKET_PATH);
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(sock_d, (struct sockaddr *)&remote, len) == -1)
	{
    perror("connect");
    printf("Check if vex_hsched deamon is running:  vex_hsched -d <config>\n");
    exit(1);
  }

	strcpy(vex_sockbuf, input[1]);
	int i = 2;
	for (i = 2; i < argc; ++i)
	{
		strcat(vex_sockbuf, " ");
		strcat(vex_sockbuf, input[i]);
	}

  if (send(sock_d, vex_sockbuf, strlen(vex_sockbuf), 0) == -1)
	{
    perror("send");
    exit(1);
 	}
  if ((recd_bytes = recv(sock_d, vex_sockbuf, MAXSOCKBUFSZ, 0)) > 0)
	{
    vex_sockbuf[recd_bytes] = '\0';
    printf("%s", vex_sockbuf);
		success = 1;
 	}
 	close(sock_d);
	return success;
}

int vex_list(int argc, char* input[])
{
	int sock_d, len;
	int recd_bytes;
	int success = 0;
	struct sockaddr_un remote;
  if ((sock_d = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
    perror("socket");
    exit(1);
  }
  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, SOCKET_PATH);
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(sock_d, (struct sockaddr *)&remote, len) == -1)
	{
    perror("connect");
    printf("Check if vex_hsched deamon is running:  vex_hsched -d <config>\n");
    exit(1);
  }

	strcpy(vex_sockbuf, input[1]);
	int i = 2;
	for (i = 2; i < argc; ++i)
	{
		strcat(vex_sockbuf, " ");
		strcat(vex_sockbuf, input[i]);
	}

  if (send(sock_d, vex_sockbuf, strlen(vex_sockbuf), 0) == -1)
	{
    perror("send");
    exit(1);
 	}
  if ((recd_bytes = recv(sock_d, vex_sockbuf, MAXSOCKBUFSZ, 0)) > 0)
	{
    vex_sockbuf[recd_bytes] = '\0';
    printf("%s\n", vex_sockbuf);
		success = 1;
 	}
 	close(sock_d);
	return success;
}

int vex_usage(char* input[])
{
  printf("*** Reserve 1 GPP resource for the given pid ***\n");
  printf("%s -q <process_identifier>", input[0]);
  printf("\n\n");

  printf("*** Reserve a given number and type of resources for a given pid ***\n");
  printf("%s -r <num_gpp> <process_identifier>", input[0]);
  printf("\n\n");
  printf("%s -r <num_gpp>:<num_gpu> <process_identifier>", input[0]);
  printf("\n\n");

  printf("*** Make node busy i.e. make it unavailable ***\n");
  printf("%s -b node:<node_name>", input[0]);
  printf("\n\n");

  printf("*** Free-up node i.e. make it available ***\n");
  printf("%s -f node:<node_name>", input[0]);
  printf("\n\n");

  printf("*** Free-up computation resources reserved earlier by a pid ***\n");
  printf("%s -f pid:<process_identifier>", input[0]);
  printf("\n\n");

  printf("*** Shows the list of all PIDs currently using resources ***");
  printf(" otherwise returns nothing ***\n");
  printf("%s -l", input[0]);
  printf("\n\n");

  printf("*** Shows the status of all NODES ***\n");
  printf("%s -n", input[0]);
  printf("\n\n");
}





















