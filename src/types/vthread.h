#ifndef SRC_TYPES_VTHREAD_H_
#define SRC_TYPES_VTHREAD_H_

#include "rtr/db/vpt.h"

struct validation_thread {
	pthread_t id;
	struct vp_table *tbl;
};

struct validation_thread *vthreads_create(void);
struct vp_table *vthreads_commit(struct validation_thread *);
void vthreads_destroy(struct validation_thread *);

#endif /* SRC_TYPES_VTHREAD_H_ */
