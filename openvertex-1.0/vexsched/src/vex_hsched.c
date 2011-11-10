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
/*********************************************************************
   Usage:  

   vex_hsched -d <file_name> -s <0|1>
    
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


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sysexits.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/vex_hsched"
#define MAX_LEN_QUEUE 50	// refer "man listen"
#define MAX_LEN_RESNAME 128
#define MAX_LEN_NODENAME 128
#define MAX_SOCKBUF_SIZE 4096
#define MAX_MACHINES 28
#define MAX_GPP_COUNT 32
#define MAX_SPP_COUNT 1024
#define MAX_PID_COUNT 65536

enum TYPE
{
	X86,
	GPU
};

// Common data structure for both types of processors
struct vex_proc
{
	int proc_type;
	int res_free;	// 1 if free, 0 if reserved
	char ident[32];	// what's the use of it
};

struct vex_resource
{
	int state; // whether node is available or not
	int num_gpp_total;
	int num_spp_total;
	int num_gpp_free;
	int num_spp_free;
	struct vex_proc vex_gpp[MAX_GPP_COUNT];
	struct vex_proc vex_spp[MAX_SPP_COUNT];
	char node_name[MAX_LEN_NODENAME];	
};

struct pid_resource
{
	int pid;
	int resource_index;
	char node_name[MAX_LEN_NODENAME];
	int num_res_gpp;
	int num_res_spp;
	struct pid_resource* next;
};
typedef struct pid_resource NODE;

int SCHED_POLICY = 0;
struct vex_resource vex_resources[MAX_MACHINES];
char vex_sockbuf[MAX_SOCKBUF_SIZE];
int TOTAL_RES;
int g_total_pid_free;
NODE* head_free;
NODE* head_reserved;

int vex_daemon(char* fname);
int vex_usage(void);
int get_avail_resource(int num_gpp, int num_spp, int total_res, int* res_index);
int find_least_loaded_resource(int num_gpp, int num_spp, int total_res, int* res_index);
int find_first_avail_resource(int num_gpp, int num_spp, int total_res, int* res_index);
int reserve_one_gpp_resource(int pid, int total_res, char* result_str);
int reserve_resources(char* input_str, int total_res, char* result_str);
int make_node_unavailable(char* node_name, int total_res, char* result_str);
void reserve_pid_nodes(void);
void reset_pid_node(NODE* node);
void free_mem_pid_nodes(void);
int read_resource_info(char* fname);
int free_resources_in_node(char* input_str, int total_res, char* result_str);
int allocate_pid_from_cache(int pid, char* n_name, int res_index, int num_gpp, int num_spp);
NODE* return_pid_to_cache(int pid);
int add_node(NODE* node);
int check_duplicate_pid(int pid);
NODE* remove_node(int pid);

void print_all_res_info();
void list_all_pids_in_use(char* result);
void list_all_nodes(char* result);

int vex_daemon(char* fname)
{
	// read complete resource info from the file supplied at start-up 
	if (fname == NULL)
	{
		printf("No conf_file specified\n");
		return;
	}
	int total_res = read_resource_info(fname);
	g_total_pid_free = MAX_PID_COUNT;
	TOTAL_RES = total_res;
	printf("Total # of NODES: %d\n", total_res);

	/********** create socket, etc. *************/
	int skt_local, skt_remote;
	int len, size, recd_bytes;
	struct sockaddr_un local, remote;
	char c;
	if ((skt_local = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
     perror("socket");
     exit(1);
  }
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, SOCKET_PATH);
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);
	if (bind(skt_local, (struct sockaddr *)&local, len) == -1)
	{
     perror("bind");
     exit(1);
  }
	if (listen(skt_local, MAX_LEN_QUEUE) == -1)
	{
     perror("listen");
     exit(1);
  }

	// reserve in-advance pid objects
	reserve_pid_nodes();

	for(;;)
	{
		printf("vex_sched deamon waiting for a client request ...\n");
		size = sizeof(remote);
		if ((skt_remote = accept(skt_local, (struct sockaddr *)&remote, &size)) == -1)
		{
      perror("accept");
      exit(1);
    }
		recd_bytes = recv(skt_remote, vex_sockbuf, MAX_SOCKBUF_SIZE, 0);
		if (recd_bytes <= 0)
		{
			perror("recv");
			printf("vex_sched deamon terminating trying to receive %d bytes\n",recd_bytes);
      exit(1);
		}
		vex_sockbuf[recd_bytes]='\0';
		c = vex_sockbuf[1]; /* skip past the "-" */

		// NOTE: 	vex_sched should identify each reserved resource against pid
		char input_str[MAX_SOCKBUF_SIZE];
		char result_string[MAX_LEN_NODENAME];
		switch(c)
		{
			case 'q':	// Reserve an arbitrary 1 GPP resource, string: -q <pid>
			{
				strcpy(input_str, &vex_sockbuf[3]);
				// str should contain only the pid value
				int pid = atoi(&input_str[0]);
				result_string[0] = '\0';
				reserve_one_gpp_resource(pid, total_res, &result_string[0]);
				break;
			}	
			// Reserve a node i.e. make unavailable, string: -b node:<node_name>
			case 'b':
			{
				strcpy(input_str, &vex_sockbuf[3]);
				printf("%s\n", input_str);
				result_string[0] = '\0';
				make_node_unavailable(input_str, total_res, &result_string[0]);
				//print_all_res_info();
				break;
			}
			// Reserve specific resources, string: -r <num_gpp>:<num_spp> <pid>
			// Reserve specific resources, string: -r <num_gpp> <pid>
			case 'r':
			{
				strcpy(input_str, &vex_sockbuf[3]);
				printf("%s\n", input_str);
				result_string[0] = '\0';
				reserve_resources(input_str, total_res, &result_string[0]);
				//print_all_res_info();
				break;
			}
			// Free-up resources, two cases:
			// string: -f pid:<pid>
			// string: -f node:<node_name>
			case 'f':
			{
				strcpy(input_str, &vex_sockbuf[3]);
				result_string[0] = '\0';
				free_resources_in_node(input_str, total_res, &result_string[0]);
				//print_all_res_info();
				break;
			}
			// List out all PIDs in use
			case 'l':
			{
				result_string[0] = '\0';
				list_all_pids_in_use(&result_string[0]);
				break;
			}
			// List out status of all NODES
			case 'n':
			{
				result_string[0] = '\0';
				list_all_nodes(&result_string[0]);
				break;
			}
			default:
			{
				strcpy(result_string, "BOGUS");
				break;
			}
		}	

		/* The clients will interpret empty result_string as an error */
    if (send(skt_remote, result_string, strlen(result_string), 0) < 0) {
       perror("send");
       printf("deamon terminating sending result.\n");
       exit(1);
    }
    close(skt_remote);
	}
	free_mem_pid_nodes();
}

int read_resource_info(char* fname)
{
	FILE *fp;
	// parse string per line in the format node_name1:num_res1:num_res2	
  if ( (fp = fopen(fname, "r")) == NULL)
  {
    err(EX_NOINPUT , "fopen for read %s \" failed", fname);
		exit(1);
  }

	char line[MAX_LEN_RESNAME+1];	// newline and '\0' char 
	char* str;
	char node[MAX_LEN_NODENAME+1];
	int num_res = 0;
	int num_x86 = 0;
	int num_gpu = 0;

	// fgets reads at most MAXLENRNAME-1 chars
	while ( fgets(line, MAX_LEN_RESNAME, fp) != NULL )
	{
		char temp[MAX_LEN_RESNAME+1];
		strcpy(temp, line);
		if (strchr(line, ':') == NULL)
		{
			printf("Wrong format of resource string -> %s\n, \
			it should be in the format -> node_name:num:num\n", temp); 
			exit(1);
		}
		if ( (str = strtok(line, ":")) == NULL)
		{
			printf("Wrong format of resource string -> %s\n", temp); 
			exit(1);
		}
		sscanf(str, "%s", node);
		if ( (str = strtok(NULL, ":")) == NULL)
		{
			printf("Wrong format of resource string -> %s\n", temp); 
			exit(1);
		}
		sscanf(str, "%d", &num_x86);
		if ( (str = strtok(NULL, "\n \t")) == NULL)
		{
			printf("Wrong format of resource string -> %s\n", temp); 
			exit(1);
		}	
		sscanf(str, "%d", &num_gpu);
		printf("%s %d %d\n", node, num_x86, num_gpu);
		// fill values read from file into the data structures
		strcpy(vex_resources[num_res].node_name, node);

		/*  At start-up all nodes are unavailable
		 *	Also no processors are free. These need to be freed up when vex_availd
		 *	makes such request
		 */
		vex_resources[num_res].state = 0; // 0 is RESERVED
		
		// XXX: Ignore vex_proc struct -- it will be removed later
		if (num_x86 != 0 )
		{
			vex_resources[num_res].num_gpp_total = num_x86;
			vex_resources[num_res].num_gpp_free = 0;
			int j = 0;
			for (j = 0; j < num_x86; ++j)
			{
				vex_resources[num_res].vex_gpp[j].proc_type = X86;
				vex_resources[num_res].vex_gpp[j].res_free = 0;
			}		
		}
		else
		{
			vex_resources[num_res].num_gpp_total = 0;
			vex_resources[num_res].num_gpp_free = 0;
		}
		if (num_gpu != 0 )
		{
			vex_resources[num_res].num_spp_total = num_gpu;
			vex_resources[num_res].num_spp_free = 0;
			int j = 0;
			for (j = 0; j < num_gpu; ++j)
			{
				vex_resources[num_res].vex_spp[j].proc_type = GPU;
				vex_resources[num_res].vex_spp[j].res_free = 0;
			}		
		}
		else
		{
			vex_resources[num_res].num_spp_total = 0;
			vex_resources[num_res].num_spp_free = 0;
		}
		++num_res;
	}
	fclose(fp);
	return num_res;
}

int reserve_one_gpp_resource(int pid, int total_res, char* result_str)
{
	int res_index = -1;
	// num_gpp = 1, num_spp = 0
	if ( !get_avail_resource(1, 0, total_res, &res_index) )
	{
		printf("No node available with the number of requested resources as free\n");
		*result_str = '\0';
		return 0;
	}
	// allocate pid_resource node from free list
	if (allocate_pid_from_cache(pid, vex_resources[res_index].node_name, res_index, 1, 0) == 0)
  {
    printf("Allocation of PID : %d failed\n", pid);
		*result_str = '\0';
    return 0;
  }
	vex_resources[res_index].num_gpp_free -= 1;
	strcpy(result_str, vex_resources[res_index].node_name);
	//print_all_res_info();
	return 1;
}

int make_node_unavailable(char* input_str, int total_res, char* result_str)
{
	char* str;
	int num_gpp = 0;
	int num_spp = 0;
	int pid = -1;
	int res_index = -1;
	int i;
  int found = 0;
	char node_name[MAX_LEN_NODENAME];
	char temp[32];
	char copy_input_str[MAX_SOCKBUF_SIZE];
	strcpy(copy_input_str, input_str);

	if (strchr(copy_input_str, ':') == NULL)
	{
		printf("ERROR: Wrong format -- No ':' present: %s\n", input_str);
		*result_str = '\0';
		return 0;
	}
	if ( (str = strtok(copy_input_str, ":")) == NULL)
	{
		printf("Blank input string %s\n", input_str);
		*result_str = '\0';
		return 0;
	}	
	sscanf(str, "%s", temp);
	if (strcmp(temp, "node") != 0)
	{
		printf("Wrong input string format %s\n", input_str);
		*result_str = '\0';
		return 0;
	}
	// make this node busy i.e. unavailable for resource allocation
	str = strtok(NULL, ":");
	sscanf(str, "%s", node_name);
	for (i = 0; i < total_res; ++i)
	{
		if (strcmp(vex_resources[i].node_name, node_name) == 0)
		{
			vex_resources[i].state = 0;
			vex_resources[i].num_gpp_free = 0;
			vex_resources[i].num_spp_free = 0;
	    printf("MAKING %s NODE UNAVAILABLE\n", node_name);
			strcpy(result_str, node_name);
      found = 1;
			break;
		}
	}
  if (found == 0)
  {
	  printf("No NODE found with this name: %s\n", node_name);
    *result_str = '\0';
		return 0;
  }
	return 1;
}

int reserve_resources(char* input_str, int total_res, char* result_str)
{
	char* str;
	int num_gpp = 0;
	int num_spp = 0;
	int pid = -1;
	int res_index = -1;
	char node_name[MAX_LEN_NODENAME];
	char copy_input_str[MAX_SOCKBUF_SIZE];
	strcpy(copy_input_str, input_str);

	if (strchr(copy_input_str, ':') != NULL)
	{
		// the format is "num:num pid"
		if ( (str = strtok(copy_input_str, ":")) == NULL)
		{
			printf("Blank input string %s\n", input_str);
			*result_str = '\0';
			return 0;
		}	
		sscanf(str, "%d", &num_gpp);
		if ( (str = strtok(NULL, " \t\n")) == NULL)
		{
			printf("Wrong input string %s\n", input_str);
			*result_str = '\0';
			return 0;
		}
		sscanf(str, "%d", &num_spp);
		if ( (str = strtok(NULL, " \n\t")) == NULL)
		{
			printf("Wrong input string %s\n", input_str);
			*result_str = '\0';
			return 0;
		}
		sscanf(str, "%d", &pid);
	}
	else
	{
		// the format is "num pid"
    if ( (str = strtok(copy_input_str, " \t")) == NULL )
    {
			printf("Wrong input string %s\n", input_str);
			*result_str = '\0';
			return 0;
    }
		sscanf(str, "%d", &num_gpp);
    if ( (str = strtok(NULL, " \t")) == NULL )
    {
			printf("Wrong input string %s\n", input_str);
			*result_str = '\0';
			return 0;
    }
		sscanf(str, "%d", &pid);
	}

	if ( !get_avail_resource(num_gpp, num_spp, total_res, &res_index) )
	{
		printf("No node available with the number of requested resources as free\n");
		*result_str = '\0';
		return 0;
	}
	// allocate pid_resource node from free list
	if (allocate_pid_from_cache(pid, vex_resources[res_index].node_name, res_index, num_gpp, num_spp) == 0)
  {
    printf("Allocation of PID : %d failed\n", pid);
		*result_str = '\0';
    return 0;
  }
  printf("Reserving RESOURCES: %d:%d\n", num_gpp, num_spp);
	vex_resources[res_index].num_gpp_free -= num_gpp;
	vex_resources[res_index].num_spp_free -= num_spp;
	strcpy(result_str, vex_resources[res_index].node_name);
	return 1;
}

int get_avail_resource(int num_gpp, int num_spp, int total_res, int* res_index)
{
	if (SCHED_POLICY == 0)
	{
		return find_first_avail_resource(num_gpp, num_spp, total_res, res_index);
	}
	else if (SCHED_POLICY == 1)
	{
		return find_least_loaded_resource(num_gpp, num_spp, total_res, res_index);
	}
	else
	{
		assert(0);
	}
}

int find_first_avail_resource(int num_gpp, int num_spp, int total_res, int* res_index)
{
	int found_gpp = 0;
	int found_spp = 0;
	int success = 0;
	int i = 0;
	// XXX: handle num_gpp = 0 --extreme case ??
	// num_spp is zero when no GPU resources are requested
	for(i = 0; i < total_res; ++i)
	{
		if (vex_resources[i].state == 0)
		{
			continue;	// this node is unavailable
		}
		if (num_gpp == 0)
		{
			printf("ERROR: NUM_GPP can't be %d\n", num_gpp);
			break;
		}
		if (vex_resources[i].num_gpp_free >= num_gpp)
		{
			found_gpp = 1;
		}
		if (num_spp != 0)
		{
			if (vex_resources[i].num_spp_free >= num_spp)
			{
				found_spp = 1;
			}
		}
		else
		{
			found_spp = 1;
		}
		if (found_gpp && found_spp)
		{
			*res_index = i;
			success = 1;
			break;
		}
	}
	if (!success)
	{
		printf("Could not find requested resource\n");
		*res_index = -1;
	}
	return success;
}

int find_least_loaded_resource(int num_gpp, int num_spp, int total_res, int* res_index)
{
	int found_gpp = 0;
	int found_spp = 0;
	int success = 0;
	int i = 0;
	int max_idx = 0;
	int max_res = 0;
	// XXX: handle num_gpp = 0 --extreme case ??
	// num_spp is zero when no GPU resources are requested
	for(i = 0; i < total_res; ++i)
	{
		if (vex_resources[i].state == 0)
		{
			continue;	// this node is unavailable
		}
		if (num_gpp == 0)
		{
			printf("ERROR: NUM_GPP can't be %d\n", num_gpp);
			break;
		}
		if (vex_resources[i].num_gpp_free >= num_gpp)
		{
			if (vex_resources[i].num_gpp_free >= max_res)
			{
				max_res = vex_resources[i].num_gpp_free;
				max_idx = i;
			}	
			found_gpp = 1;
		}
		if (num_spp != 0)
		{
			if (vex_resources[i].num_spp_free >= num_spp)
			{
				found_spp = 1;
			}
		}
		else
		{
			found_spp = 1;
		}
	}
	if (found_gpp && found_spp)
	{
		*res_index = max_idx;
		success = 1;
	}
	if (!success)
	{
		*res_index = -1;
	}
	return success;
}

int free_resources_in_node(char* input_str, int total_res, char* result_str)
{
	// two possible formats
	// pid:2345
	// node:n1
	char* str;
	char temp[32];
	char node_name[MAX_LEN_NODENAME];
	char pid_str[32];
	char copy_input_str[MAX_SOCKBUF_SIZE];
	strcpy(copy_input_str, input_str);

	if (strchr(copy_input_str, ':') == NULL)
	{
		printf("ERROR: Wrong format -- No ':' present: %s\n", copy_input_str);
		*result_str = '\0';
		return 0;
	}
	if ( (str = strtok(copy_input_str, ":")) == NULL)
	{
		printf("Blank input string %s\n", input_str);
		*result_str = '\0';
		return 0;
	}	
	sscanf(str, "%s", temp);

	if (strcmp(temp, "node") == 0)
	{
		// First case: a node is made available
		int i = 0;
    int found = 0;
		if ( (str = strtok(NULL, ": \n\t")) == NULL)
		{
			printf("Wrong format of input string %s\n", input_str);
			*result_str = '\0';
			return 0;
		}
		sscanf(str, "%s", node_name);
		for(i = 0; i < total_res; ++i)
		{
			if (strcmp(vex_resources[i].node_name, node_name) == 0)
			{
				vex_resources[i].state = 1; // node is available
				vex_resources[i].num_gpp_free = vex_resources[i].num_gpp_total;
				vex_resources[i].num_spp_free = vex_resources[i].num_spp_total;
				strcpy(result_str, vex_resources[i].node_name);
        found = 1;
				break;
			}
		}
    if (found == 0)
    {
	    printf("No NODE found with this name: %s\n", node_name);
    }
	}
	else if (strcmp(temp, "pid") == 0)
	{
		if ( (str = strtok(NULL, ": \n\t")) == NULL )
		{
			printf("Wrong format of input string %s\n", input_str);
			*result_str = '\0';
			return 0;
		}
		sscanf(str, "%s", pid_str);
		int pid;
		NODE* pid_node;
		pid = atoi(&pid_str[0]);
		if ( (pid_node = return_pid_to_cache(pid)) == NULL )
		{
			printf("ERROR: NODE not found\n");
			*result_str = '\0';
			return 0;
		}
		// should check that the node names match
		if (strcmp(vex_resources[pid_node->resource_index].node_name,
				pid_node->node_name) != 0)
		{
			printf("ERROR: node_names don't match\n");
			*result_str = '\0';
			return 0;
		}
		if (vex_resources[pid_node->resource_index].state == 0)
		{
			printf("ERROR: Trying to free-up pid: %d on an unavailable node\n", pid);
			*result_str = '\0';
			return 0;
		}
		printf("REMOVE_NODE SUCCESS\n");
		vex_resources[pid_node->resource_index].num_gpp_free += pid_node->num_res_gpp;
		vex_resources[pid_node->resource_index].num_spp_free += pid_node->num_res_spp;
		strcpy(result_str, vex_resources[pid_node->resource_index].node_name);
		// Reset all members of the node back to init state
		reset_pid_node(pid_node);
	}
	else
	{
		printf("Wrong format %s\n", input_str);
		*result_str = '\0';
		return 0;
	}
	return 1;	
}

int allocate_pid_from_cache(int pid, char* n_name, int res_index, int num_gpp, int num_spp)
{
  if (check_duplicate_pid(pid) == 0)
  {
    return 0;
  }
	// add node to the list of reserved nodes
	NODE* node;
	node = head_free;	
	head_free = node->next;
	node->pid = pid;
	node->resource_index = res_index;
	strcpy(node->node_name, n_name);
	node->num_res_gpp = num_gpp;
	node->num_res_spp = num_spp;
	// Add node into the reserved list
	if (add_node(node) < 0)
  {
    return 0;
  }
	--g_total_pid_free;
	int count = 0;
	int count_f = 0;
	NODE* curr;
	curr = head_reserved;
	while (curr != NULL)
	{
		++count;
		curr = curr->next;
	}

	curr = head_free;
	while (curr != NULL)
	{
		++count_f;
		curr = curr->next;
	}
	printf("allocate_pid_from_cache: Total reserved: %d and free: %d\n", count, count_f);
	return 1;
}

NODE* return_pid_to_cache(int pid)
{
	// remove from reserved linked list and add back to free list 
	NODE* node;
	// Remove node from the reserved list
	if( (node = remove_node(pid)) == NULL)
	{
		printf("ERROR: Node not found in reserved list, pid: %d\n", pid);
		return NULL;
	}

	node->next = head_free;
	head_free = node;
	++g_total_pid_free;

	NODE* curr;
	curr = head_free;
	int count = 0;
	int count_r = 0;
	while (curr != NULL)
	{
		++count;
		curr = curr->next;
	}

	curr = head_reserved;
	while (curr != NULL)
	{
		++count_r;
		curr = curr->next;
	}
	printf("return_pid_to_cache: Total nodes reserved: %d and free: %d\n", count_r, count);

	return node;
}

int check_duplicate_pid(int pid)
{
	/* check if this pid already exists in reserved list*/
	NODE* curr;
	curr = head_reserved;
	while(curr != NULL)
	{
    if (pid == curr->pid)
    {
      printf("This PID : %d already exists !! ", pid);
      printf("First free this pid before reserving\n");
      return 0;
    }
    else if (pid > curr->pid)
    {
      curr = curr->next;
    }
    else
    {
      return 1;
    }
  }
  return 1;
}

int add_node(NODE* pid_node)
{
	/* add to reserved list - sorted order of PIDs*/
	NODE* curr;
	NODE* prev;
	curr = head_reserved;
	prev = head_reserved;
	// check for boundary conditions:
	// new node could be the first node OR in first position
	if ( (head_reserved == NULL) || (pid_node->pid < head_reserved->pid) )
	{
		pid_node->next = head_reserved;
		head_reserved = pid_node;
		return 1;
	}

	while(curr != NULL)
	{
		if (pid_node->pid > curr->pid)
		{
			prev = curr;
			curr = curr->next;
		}
		else
		{
			break;
		}
	}
	prev->next = pid_node;
	pid_node->next = curr;
  return 1;
}

NODE* remove_node(int pid)
{
	// remove from reserved list
	NODE* curr;
	NODE* prev;
	NODE* result = NULL;
	curr = head_reserved;
	prev = head_reserved;
	// check for error condition
	if (head_reserved == NULL)
	{
		printf("ERROR: list is empty\n");
		return NULL;
	}
	if (pid == head_reserved->pid)
	{
		result = head_reserved;
		head_reserved = head_reserved->next;
		printf("First node\n");
		return result;
	}
	while(curr != NULL)
	{
		if (pid > curr->pid)
		{
			prev = curr;
			curr = curr->next;
		}
		else if (pid == curr->pid)
		{
			result = curr;
			prev->next = curr->next;
			break;
		}
		else
		{
			printf("ERROR: PID %d not found\n", pid);
			return NULL;
		}
	}
	if (curr == NULL)
	{
		printf("ERROR: PID %d not found\n", pid);
		return NULL;
	}
	return result;
}

void reserve_pid_nodes()
{
	int i = 0;
	NODE* curr;
	head_free = head_reserved = NULL;
	head_free = (NODE*) malloc(sizeof(NODE));
	head_free->next = NULL;
	curr = head_free;
	for (i = 1; i < MAX_PID_COUNT; ++i)
	{
		NODE* node = (NODE*) malloc(sizeof(NODE));
		node->pid = -1;
		node->resource_index = -1;
		node->node_name[0] = '\0';
		node->num_res_gpp = 0;
		node->num_res_spp = 0;
		node->next = NULL;
		curr->next = node;
		curr = curr->next;
	}
	curr = head_free;
	int count = 0;
	while (curr != NULL)
	{
		++count;
		curr = curr->next;
	}
	printf("TOTAL PID ELEMENTS: %d\n",  count);
}

void reset_pid_node(NODE* node)
{
	node->pid = -1;
	node->resource_index = -1;
	node->node_name[0] = '\0';
	node->num_res_gpp = 0;
	node->num_res_spp = 0;
	// CAUTION: do not touch node->next !! 
}

void free_mem_pid_nodes()
{
	NODE* curr;
	NODE* temp;
	curr = head_free;
	while(curr != NULL)
	{
		temp = curr->next;
		free(curr);
		curr = temp;
	}
	curr = head_reserved;
	while(curr != NULL)
	{
		temp = curr->next;
		free(curr);
		curr = temp;
	}
}

void print_all_res_info()
{
	int i = 0;
	for (i = 0; i < TOTAL_RES; ++i)
	{
		if (vex_resources[i].state == 0)
		{
			printf("Node  RESERVED: %s\n", vex_resources[i].node_name);
		}
		else
		{
			printf("Node AVAILABLE: %s %d %d\n", vex_resources[i].node_name,
																			  	 vex_resources[i].num_gpp_free,
																			  	 vex_resources[i].num_spp_free);
		}
	}
	NODE* curr;
	curr = head_reserved;
	while (curr != NULL)
	{
		printf("%d %d %s %d %d\n", curr->pid, curr->resource_index, curr->node_name,
															 curr->num_res_gpp, curr->num_res_spp); 
	  curr = curr->next;														 
	}
	printf("Total PID free: %d\n", g_total_pid_free);
}

void list_all_pids_in_use(char* result)
{
	NODE* curr;
	char temp[32];
	curr = head_reserved;
	while (curr != NULL)
	{
		sprintf(temp, "%d ", curr->pid);
		strcat(result, temp);
	  curr = curr->next;														 
	}
}

void list_all_nodes(char* result)
{
	int i = 0;
  char temp[128];
	for (i = 0; i < TOTAL_RES; ++i)
	{
		if (vex_resources[i].state == 0)
		{
			sprintf(temp, "RESERVED: %s\n", vex_resources[i].node_name);
		  strcat(result, temp);
		}
		else
		{
			sprintf(temp, "AVAILABLE: %s\n", vex_resources[i].node_name);
		  strcat(result, temp);
		}
	}
}

int vex_usage(void)
{
	printf("Usage: vex_hsched -d <conf_file> -s <0|1>\n");
	printf("-d : specify config file\n");
	printf("-s : specify scheduling policy :: \n");
	printf("     '0' for first available and '1' for least loaded\n");
}

int main(int argc, char* argv[])
{
	int num_args = argc;
	char c;
	char* dvalue = NULL;
	char* svalue = NULL;
	int index = 0;
	if (num_args < 3 || num_args > 5)
	{
	  printf("Wrong number of arguments !!\n");
		vex_usage();
		return;
	}

	while ( (c = getopt(argc, argv, "d:s:")) != -1)
	{
		switch(c)
		{
			case 'd':
				dvalue = optarg;
				break;
			case 's':
				svalue = optarg;
				break;
			case '?':
				if (optopt == 'd')
				{
					printf ("Option -%c requires an argument\n", optopt);
				}	
				else if (optopt == 's')
				{
					printf ("Option -%c requires an argument\n", optopt);
				}
				return 1;
			default:
				vex_usage();
				return;
		}
	}
	if (dvalue == NULL || svalue == NULL)
	{
		printf("Missing argument !!\n");
		vex_usage();
		return;
	}
	if (strchr(dvalue, '-') != NULL)
	{
		printf("Missing argument for '-d' option\n");
		return;
	}
	if (strchr(svalue, '-') != NULL)
	{
		printf("Missing argument for '-s' option\n");
		return;
	}

	int policy = atoi(svalue);
	if (policy < 0 || policy > 1)
	{
		printf("Wrong value for Scheduling Policy : %d\n", policy);
		vex_usage();
		return;
	}	
	SCHED_POLICY = atoi(svalue);
	printf("Scheduling Policy : %d\n", SCHED_POLICY);
	vex_daemon(dvalue);
}
