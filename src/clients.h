#ifndef SRC_CLIENTS_H_
#define SRC_CLIENTS_H_

#include <stdbool.h>
#include "rtr/pdu.h"
#include "rtr/db/vrp.h"

struct client {
	int fd;

	serial_t serial_number;
	bool serial_number_set;
};

int clients_db_init(void);

int clients_add(struct rtr_client *);
void clients_update_serial(int, serial_t);
void clients_forget(int);
typedef int (*clients_foreach_cb)(struct client const *, void *);
int clients_foreach(clients_foreach_cb, void *);
serial_t clients_get_min_serial(void);

void clients_db_destroy(void);

#endif /* SRC_CLIENTS_H_ */
