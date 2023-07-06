#include "internal_pool.h"

#include <stddef.h>

/*
 * This is a basic wrapper for thread_pool functions, but the allocated pool
 * lives at the main thread.
 *
 * Additional threads that must be spawned during execution (those that aren't
 * related to the validation or server thread pool tasks) can be pushed here.
 */

#define INTERNAL_POOL_MAX 10

static struct thread_pool *pool;

int
internal_pool_init(void)
{
	int error;

	pool = NULL;
	error = thread_pool_create("Internal", INTERNAL_POOL_MAX, &pool);
	if (error)
		return error;

	return 0;
}

void
internal_pool_push(char const *task_name, thread_pool_task_cb cb, void *arg)
{
	thread_pool_push(pool, task_name, cb, arg);
}

void
internal_pool_cleanup(void)
{
	thread_pool_destroy(pool);
}
