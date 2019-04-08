#ifndef SRC_CLIENTS_H_
#define SRC_CLIENTS_H_

#include <arpa/inet.h>

struct client {
	int fd;
	sa_family_t sin_family;
	union {
		struct in_addr sin;
		struct in6_addr sin6;
	} addr;
	in_port_t sin_port;
	uint8_t rtr_version;
};

int clients_db_init(void);
int update_client(int, struct sockaddr_storage *, uint8_t);
size_t client_list(struct client **);

void clients_forget(int);
void clients_db_destroy(void);

#endif /* SRC_CLIENTS_H_ */
