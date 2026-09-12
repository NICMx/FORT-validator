#ifndef SRC_TYPES_VTHREAD_H_
#define SRC_TYPES_VTHREAD_H_

#include "rtr/db/db_table.h"

struct validation_thread {
	pthread_t id;
	struct db_table *tbl;
};

struct validation_thread *vthreads_create(void);
struct db_table *vthreads_commit(struct validation_thread *);
void vthreads_destroy(struct validation_thread *);

#endif /* SRC_TYPES_VTHREAD_H_ */
