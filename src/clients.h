#ifndef SRC_CLIENTS_H_
#define SRC_CLIENTS_H_

#include <arpa/inet.h>
#include <time.h>

struct client {
	int fd;
	sa_family_t sin_family;
	union {
		struct in_addr sin_addr;
		struct in6_addr sin6_addr;
	};
	in_port_t sin_port;
	u_int8_t rtr_version;
	/* TODO forget clients when the expiration time is reached */
	time_t expiration;
};

int clients_db_init(void);
int update_client(int fd, struct sockaddr_storage *, u_int8_t, time_t);
size_t client_list(struct client **);
void clients_db_destroy(void);

#endif /* SRC_CLIENTS_H_ */
