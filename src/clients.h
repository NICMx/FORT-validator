#ifndef SRC_CLIENTS_H_
#define SRC_CLIENTS_H_

#include <pthread.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "rtr/pdu.h"
#include "rtr/db/vrp.h"

struct client {
	int fd;
	struct sockaddr_storage addr;
	/*
	 * The join should be made when the db is cleared, so the main process
	 * should do it.
	 */
	pthread_t tid;

	serial_t serial_number;
	bool serial_number_set;

	uint8_t rtr_version;
	bool rtr_version_set;
};

int clients_db_init(void);

int clients_add(int, struct sockaddr_storage, pthread_t);
void clients_update_serial(int, serial_t);
void clients_forget(int);
typedef int (*clients_foreach_cb)(struct client const *, void *);
int clients_foreach(clients_foreach_cb, void *);
int clients_get_min_serial(serial_t *);
int clients_get_addr(int, struct sockaddr_storage *);

int clients_set_rtr_version(int, uint8_t);
int clients_get_rtr_version_set(int, bool *, uint8_t *);

typedef int (*join_thread_cb)(pthread_t, void *);
void clients_db_destroy(join_thread_cb, void *);

#endif /* SRC_CLIENTS_H_ */
