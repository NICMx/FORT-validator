#ifndef SRC_THREAD_THREAD_POOL_H_
#define SRC_THREAD_THREAD_POOL_H_

#include <stdbool.h>

/*
 * THREAD POOL THREADS ARE NOT ALLOWED TO SLEEP FOR LONG PERIODS OF TIME.
 */

/* Thread pool base struct */
struct thread_pool;

int thread_pool_create(char const *, unsigned int, struct thread_pool **);
void thread_pool_destroy(struct thread_pool *);

typedef void (*thread_pool_task_cb)(void *);
void thread_pool_push(struct thread_pool *, char const *, thread_pool_task_cb,
    void *);

bool thread_pool_avail_threads(struct thread_pool *);
void thread_pool_wait(struct thread_pool *);

#endif /* SRC_THREAD_THREAD_POOL_H_ */
