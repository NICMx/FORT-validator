#include "thread/thread_pool.h"

#include <sys/queue.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

/*
 * Mainly based on a solution proposed by Ivaylo Josifov (from VarnaIX)
 * and from https://nachtimwald.com/2019/04/12/thread-pool-in-c/
 */

/* Task to be done by each thread */
struct task {
	thread_pool_task_cb cb;
	void *arg;
	TAILQ_ENTRY(task) next;
};

/* Tasks queue (utilized as FIFO) */
TAILQ_HEAD(task_queue, task);

struct thread_pool {
	pthread_mutex_t lock;
	/* Work/wait conditions, utilized accordingly to their names */
	pthread_cond_t working_cond;
	pthread_cond_t waiting_cond;
	/* Currently working thread */
	unsigned int working_count;
	/* Total number of spawned threads */
	unsigned int thread_count;
	/* Use to stop all the threads */
	bool stop;
	/* Queue of pending tasks to attend */
	struct task_queue queue;
};

static void
thread_pool_lock(struct thread_pool *pool)
{
	int error;

	error = pthread_mutex_lock(&(pool->lock));
	if (error)
		pr_crit("pthread_mutex_lock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    error);
}

static void
thread_pool_unlock(struct thread_pool *pool)
{
	int error;

	error = pthread_mutex_unlock(&(pool->lock));
	if (error)
		pr_crit("pthread_mutex_unlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    error);
}

static int
task_create(thread_pool_task_cb cb, void *arg, struct task **result)
{
	struct task *tmp;

	tmp = malloc(sizeof(struct task));
	if (tmp == NULL)
		return pr_enomem();

	tmp->cb = cb;
	tmp->arg = arg;

	*result = tmp;
	return 0;
}

static void
task_destroy(struct task *task)
{
	free(task);
}

/* Get the TAIL, remove the ref from @queue, don't forget to free the task! */
static struct task *
task_queue_pull(struct task_queue *queue)
{
	struct task *tmp;

	tmp = TAILQ_LAST(queue, task_queue);
	TAILQ_REMOVE(queue, tmp, next);

	return tmp;
}

/* Insert the task at the HEAD */
static void
task_queue_push(struct task_queue *queue, struct task *task)
{
	TAILQ_INSERT_HEAD(queue, task, next);
}

/*
 * Poll for pending tasks at the pool queue. Called by each spawned thread.
 *
 * Once a task is available, at least one thread of the pool will process it.
 *
 * The call ends only if the pool wishes to be stopped.
 */
static void *
tasks_poll(void *arg)
{
	struct thread_pool *pool = arg;
	struct task *task;

	/* The thread has started, send the signal */
	thread_pool_lock(pool);
	pthread_cond_signal(&(pool->waiting_cond));
	thread_pool_unlock(pool);

	while (true) {
		thread_pool_lock(pool);

		while (TAILQ_EMPTY(&(pool->queue)) && !pool->stop)
			pthread_cond_wait(&(pool->working_cond), &(pool->lock));

		if (pool->stop)
			break;

		/* Pull the tail */
		task = task_queue_pull(&(pool->queue));
		pool->working_count++;
		pr_op_debug("Working on task #%u", pool->working_count);
		thread_pool_unlock(pool);

		if (task != NULL) {
			task->cb(task->arg);
			/* Now releasing the task */
			task_destroy(task);
			pr_op_debug("Task ended");
		}

		thread_pool_lock(pool);
		pool->working_count--;
		if (!pool->stop && pool->working_count == 0 &&
		    TAILQ_EMPTY(&(pool->queue)))
			pthread_cond_signal(&(pool->waiting_cond));

		thread_pool_unlock(pool);
	}

	/* The thread will cease to exist */
	pool->thread_count--;
	pthread_cond_signal(&(pool->waiting_cond));
	thread_pool_unlock(pool);

	return NULL;
}

/*
 * Wait a couple of seconds to be sure the thread has started and is ready to
 * work
 */
static int
thread_pool_thread_wait_start(struct thread_pool *pool)
{
	struct timespec tmout = {
	    .tv_sec = 0 ,
	    .tv_nsec = 0
	};
	int error;

	/* 2 seconds to start a thread */
	clock_gettime(CLOCK_REALTIME, &tmout);
	tmout.tv_sec += 2;

	error = pthread_cond_timedwait(&(pool->waiting_cond), &(pool->lock),
	    &tmout);
	if (error)
		return pr_op_errno(error, "Waiting thread to start");

	return 0;
}

static int
tpool_thread_spawn(struct thread_pool *pool, thread_pool_task_cb entry_point)
{
	pthread_attr_t attr;
	pthread_t thread_id;
	int error;

	memset(&thread_id, 0, sizeof(pthread_t));

	error = pthread_attr_init(&attr);
	if (error)
		return pr_op_errno(error, "Calling pthread_attr_init()");

	/* Use 2MB (default in most 64 bits systems) */
	error = pthread_attr_setstacksize(&attr, 1024 * 1024 * 2);
	if (error)
		return pr_op_errno(error,
		    "Calling pthread_attr_setstacksize()");

	error = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (error)
		return pr_op_errno(error,
		    "Calling pthread_attr_setdetachstate()");

	thread_pool_lock(pool);
	error = pthread_create(&thread_id, &attr, entry_point, pool);
	pthread_attr_destroy(&attr);
	if (error) {
		thread_pool_unlock(pool);
		return pr_op_errno(error, "Spawning pool thread");
	}

	error = thread_pool_thread_wait_start(pool);
	if (error) {
		thread_pool_unlock(pool);
		return error;
	}
	thread_pool_unlock(pool);

	return 0;
}

int
thread_pool_create(unsigned int threads, struct thread_pool **pool)
{
	struct thread_pool *tmp;
	unsigned int i;
	int error;

	tmp = malloc(sizeof(struct thread_pool));
	if (tmp == NULL)
		return pr_enomem();

	/* Init locking */
	error = pthread_mutex_init(&(tmp->lock), NULL);
	if (error) {
		error = pr_op_errno(error, "Calling pthread_mutex_init()");
		goto free_tmp;
	}

	/* Init conditional to signal pending work */
	error = pthread_cond_init(&(tmp->working_cond), NULL);
	if (error) {
		error = pr_op_errno(error,
		    "Calling pthread_cond_init() at working condition");
		goto free_mutex;
	}

	/* Init conditional to signal no pending work */
	error = pthread_cond_init(&(tmp->waiting_cond), NULL);
	if (error) {
		error = pr_op_errno(error,
		    "Calling pthread_cond_init() at waiting condition");
		goto free_working_cond;
	}

	TAILQ_INIT(&(tmp->queue));
	tmp->stop = false;
	tmp->working_count = 0;
	tmp->thread_count = threads;

	for (i = 0; i < threads; i++) {
		error = tpool_thread_spawn(tmp, tasks_poll);
		if (error) {
			thread_pool_destroy(tmp);
			return error;
		}
		pr_op_debug("Pool thread #%u spawned", i);
	}

	*pool = tmp;
	return 0;
free_working_cond:
	pthread_cond_destroy(&(tmp->working_cond));
free_mutex:
	pthread_mutex_destroy(&(tmp->lock));
free_tmp:
	free(tmp);
	return error;
}

void
thread_pool_destroy(struct thread_pool *pool)
{
	struct task_queue *queue;
	struct task *tmp;

	/* Remove all pending work and send the signal to stop it */
	thread_pool_lock(pool);
	queue = &(pool->queue);
	while (!TAILQ_EMPTY(queue)) {
		tmp = TAILQ_FIRST(queue);
		TAILQ_REMOVE(queue, tmp, next);
		task_destroy(tmp);
	}
	pool->stop = true;
	pthread_cond_broadcast(&(pool->working_cond));
	thread_pool_unlock(pool);

	/* Wait for all to end */
	thread_pool_wait(pool);

	pthread_cond_destroy(&(pool->waiting_cond));
	pthread_cond_destroy(&(pool->working_cond));
	pthread_mutex_destroy(&(pool->lock));
	free(pool);
}

/*
 * Push a new task to @pool, the task to be executed is @cb with the argument
 * @arg.
 */
int
thread_pool_push(struct thread_pool *pool, thread_pool_task_cb cb, void *arg)
{
	struct task *task;
	int error;

	task = NULL;
	error = task_create(cb, arg, &task);
	if (error)
		return error;

	thread_pool_lock(pool);
	task_queue_push(&(pool->queue), task);
	thread_pool_unlock(pool);

	/* There's work to do! */
	pthread_cond_broadcast(&(pool->working_cond));

	return 0;
}

/* Waits for all pending tasks at @poll to end */
void
thread_pool_wait(struct thread_pool *pool)
{
	thread_pool_lock(pool);
	while (true) {
		pr_op_debug("Waiting all tasks from the pool to end");
		if ((!pool->stop && pool->working_count != 0) ||
		    (pool->stop && pool->thread_count != 0))
			pthread_cond_wait(&(pool->waiting_cond), &(pool->lock));
		else
			break;
	}
	thread_pool_unlock(pool);
	pr_op_debug("Waiting has ended, all tasks have finished");
}
