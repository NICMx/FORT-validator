#ifndef SRC_INTERNAL_POOL_H_
#define SRC_INTERNAL_POOL_H_

#include "thread/thread_pool.h"

int internal_pool_init(void);
int internal_pool_push(thread_pool_task_cb, void *);
void internal_pool_cleanup(void);

#endif /* SRC_INTERNAL_POOL_H_ */
