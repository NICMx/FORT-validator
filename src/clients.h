#ifndef SRC_CLIENTS_H_
#define SRC_CLIENTS_H_

#include <stdbool.h>
#include <netinet/in.h>
#include "rtr/pdu.h"
#include "rtr/db/vrp.h"

struct client {
	int fd;
	struct sockaddr_storage addr;

	serial_t serial_number;
	bool serial_number_set;

	uint8_t rtr_version;
	bool rtr_version_set;
};

int clients_db_init(void);

int clients_add(int, struct sockaddr_storage);
void clients_update_serial(int, serial_t);

typedef int (*clients_foreach_cb)(struct client *, void *);
void clients_forget(int, clients_foreach_cb, void *);
int clients_foreach(clients_foreach_cb, void *);

int clients_get_min_serial(serial_t *);

int clients_set_rtr_version(int, uint8_t);
int clients_get_rtr_version_set(int, bool *, uint8_t *);

int clients_terminate_all(clients_foreach_cb, void *);
void clients_db_destroy(void);

#endif /* SRC_CLIENTS_H_ */
