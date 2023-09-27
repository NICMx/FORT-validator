#ifndef RTR_RTR_H_
#define RTR_RTR_H_

#include <arpa/inet.h>
#include <netinet/in.h>

struct rtr_server {
	int fd;
	/* Printable address to which the server was bound. */
	char *addr;
};

struct rtr_client {
	int fd;
	char addr[INET6_ADDRSTRLEN]; /* Printable address of the client. */
	int rtr_version; /* -1: unset; > 0: version number */
};

int rtr_start(void);
void rtr_stop(void);

typedef int (*rtr_foreach_client_cb)(struct rtr_client const *, void *arg);
int rtr_foreach_client(rtr_foreach_client_cb, void *);

#endif /* RTR_RTR_H_ */
