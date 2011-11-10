typedef struct Qel Qel;
typedef struct Queue Queue;

struct Qel
{
	Qel *next;
	void *p;
};

struct Queue
{
	pthread_mutex_t lk;
	Qel *head;
	Qel *tail;
};

Queue 	*qalloc(void);
void 	*recvq(Queue *);
void 	qfree(Queue *);
int    	sendq(Queue *, void *);
int	pollq(Queue *q);
