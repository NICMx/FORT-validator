#include "internal_pool.h"

#include <stddef.h>

/*
 * This is a basic wrapper for thread_pool functions, but the allocated pool
 * lives at the main thread.
 *
 * Additional threads that must be spawned during execution (those that aren't
 * related to the validation or server thread pool tasks) can be pushed here.
 */

#define INTERNAL_POOL_MAX 5

struct thread_pool *pool;

int
internal_pool_init(void)
{
	int error;

	pool = NULL;
	error = thread_pool_create(INTERNAL_POOL_MAX, &pool);
	if (error)
		return error;

	return 0;
}

int
internal_pool_push(thread_pool_task_cb cb, void *arg)
{
	return thread_pool_push(pool, cb, arg);
}

void
internal_pool_cleanup(void)
{
	thread_pool_destroy(pool);
}
