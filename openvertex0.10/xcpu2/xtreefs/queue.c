#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
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
#include <pthread.h>

#include "queue.h"

Queue*
qalloc(void)
{
    Queue *q;
	int n;

    q = calloc(1, sizeof(*q));
    if(q == NULL)
        return NULL;
	
	while((n = pthread_mutex_init(&q->lk, NULL)) != 0)
		if(n != EAGAIN)
			return NULL;

    return q;
}

void
qfree(Queue *q)
{
	Qel *e, *ne;

	pthread_mutex_lock(&q->lk);
	e = q->head;
	while(e != NULL) {
		ne = e->next;
		free(e);
		e = ne;
	}
	pthread_mutex_unlock(&q->lk);
	free(q);
}

int
sendq(Queue *q, void *p)
{
    Qel *e;

    e = malloc(sizeof(Qel));
	if(e == NULL)
		return -1;
    pthread_mutex_lock(&q->lk);
    e->p = p;
    e->next = NULL;
    if(q->head == NULL)
        q->head = e;
    else
        q->tail->next = e;
    q->tail = e;
    pthread_mutex_unlock(&q->lk);
    return 0;
}

void *
recvq(Queue *q)
{   
    void *p;
    Qel *e;

	if(q->head == NULL)
		return NULL;
    pthread_mutex_lock(&q->lk);
    e = q->head;
    q->head = e->next;
    pthread_mutex_unlock(&q->lk);
    p = e->p;
    free(e);
    return p;
}

int
pollq(Queue *q)
{   

	if(q->head == NULL)
		return 0;
	return 1;
}
