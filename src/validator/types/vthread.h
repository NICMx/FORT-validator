#ifndef VALIDATOR_TYPES_VTHREAD_H_
#define VALIDATOR_TYPES_VTHREAD_H_

#include <pthread.h>

#include "validator/db/db_table.h"

struct validation_thread {
	pthread_t id;
	struct db_table *tbl;
};

struct validation_thread *vthreads_create(void);
struct db_table *vthreads_commit(struct validation_thread *);
void vthreads_destroy(struct validation_thread *);

#endif /* VALIDATOR_TYPES_VTHREAD_H_ */
