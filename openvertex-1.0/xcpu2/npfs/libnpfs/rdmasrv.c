#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include "npfs.h"
#include "npfsimpl.h"
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

typedef struct Rdmasrv Rdmasrv;
struct Rdmasrv {
	struct rdma_cm_id *listen_id;
	struct rdma_event_channel *event_channel;
	struct sockaddr_in addr;
	int shutdown;
	pthread_t thread;
};

extern Nptrans *np_rdmatrans_create(struct rdma_cm_id *cmid, int q_depth, int msize);

static void rdmasrv_start(Npsrv *srv);
static void rdmasrv_shutdown(Npsrv *srv);
static void rdmasrv_destroy(Npsrv *srv);
static void *rdmasrv_listenproc(void *a);

Npsrv*
np_rdmasrv_create(int nwthreads, int *port)
{
	Npsrv *srv;
	Rdmasrv *rdma;
	int ret;

	rdma = malloc(sizeof(struct Rdmasrv));
	if (!rdma)
		return NULL;

	rdma->event_channel = rdma_create_event_channel();
	if (!rdma->event_channel) {
		np_werror("Can't create event channel", EIO);
		goto error;
	}

	ret = rdma_create_id(rdma->event_channel, &rdma->listen_id,
			     NULL, RDMA_PS_TCP);
	if (ret) {
		np_werror("Can't create an id", ret);
		goto error;
	}
	
	rdma->addr.sin_family = AF_INET;
	rdma->addr.sin_port = htons(*port);
	rdma->addr.sin_addr.s_addr = htonl(INADDR_ANY);
	ret = rdma_bind_addr(rdma->listen_id, (struct sockaddr *)&rdma->addr);
	if (ret) {
		np_werror("Can't bind", ret);
		goto error;
	}

	srv = np_srv_create(nwthreads);
	srv->srvaux = rdma;
	srv->start = rdmasrv_start;
	srv->shutdown = rdmasrv_shutdown;
	srv->destroy = rdmasrv_destroy;

	return srv;

 error:
	free(rdma);
	return NULL;
}

static void
rdmasrv_start(Npsrv *srv)
{
	int n;
	Rdmasrv *rdma;

	rdma = srv->srvaux;
	n = rdma_listen(rdma->listen_id, 1);
	if (n < 0) {
		np_uerror(n);
		return;
	}

	n = pthread_create(&rdma->thread, NULL, rdmasrv_listenproc, srv);
	if (n)
		np_uerror(n);
}

static void
rdmasrv_shutdown(Npsrv *srv)
{
	Rdmasrv *rdma;

	rdma = srv->srvaux;
	rdma->shutdown = 1;
	if (rdma->listen_id)
		rdma_destroy_id(rdma->listen_id);

	rdma->listen_id = NULL;
}

static void
rdmasrv_destroy(Npsrv *srv)
{
	Rdmasrv *rdma;
	void *ret;

	rdma = srv->srvaux;
	rdmasrv_shutdown(srv);
	pthread_join(rdma->thread, &ret);
	free(rdma);
	srv->srvaux = NULL;
}

static void *
rdmasrv_listenproc(void *a)
{
	int ret;
	Npsrv *srv;
	Npconn *conn;
	Nptrans *trans;
	Rdmasrv *rdma;
	struct rdma_cm_event *event;
	struct rdma_cm_id *cmid;
	enum rdma_cm_event_type etype;

	srv = a;
	rdma = srv->srvaux;
	while (!rdma->shutdown) {
		ret = rdma_get_cm_event(rdma->event_channel, &event);
		if (ret)
			goto error;

		cmid = (struct rdma_cm_id *)event->id;
		etype = event->event;
		rdma_ack_cm_event(event);

		switch (etype) {
		case RDMA_CM_EVENT_CONNECT_REQUEST:
			printf("Connection request\n");
			trans = np_rdmatrans_create(cmid, srv->nwthread, srv->msize);
			if (trans) {
				conn = np_conn_create(srv, trans);
				cmid->context = conn;
				np_srv_add_conn(srv, conn);
			}
			break;

		case RDMA_CM_EVENT_ESTABLISHED:
			printf("Connection established\n");
			break;

		case RDMA_CM_EVENT_DISCONNECTED:
			printf("Connection shutting down\n");
			conn = cmid->context;
			np_conn_shutdown(conn);
			break;

		default:
			fprintf(stderr, "event %d received waiting for a connect request\n",
				etype);
		}
	}
	return NULL;

 error:
	fprintf(stderr, "shutting down the server with error %d\n", ret);
	return 0;
}
