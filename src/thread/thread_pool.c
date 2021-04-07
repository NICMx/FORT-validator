#include "thread/thread_pool.h"

#include <sys/queue.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

/*
 * Mainly based on a solution proposed by Ivaylo Josifov (from VarnaIX)
 * and from https://nachtimwald.com/2019/04/12/thread-pool-in-c/
 */

/*
 * Glossary:
 *
 * - Worker Thread: A thread in the pool.
 * - Working Thread: A worker thread, currently doing work.
 * - Parent Thread: The thread that owns the pool, and wants to defer work to
 *   the worker threads.
 * - Task: Work that will be handled by a Worker Thread.
 */

/* Task to be done by each Worker Thread. */
struct task {
	thread_pool_task_cb cb;
	void *arg;
	TAILQ_ENTRY(task) next;
};

/* A collection of Tasks, used as FIFO. */
TAILQ_HEAD(task_queue, task);

struct thread_pool {
	pthread_mutex_t lock;
	/*
	 * Used by the Parent Thread to wake up Worker Threads when there's
	 * work.
	 */
	pthread_cond_t working_cond;
	/*
	 * Used by Working Threads to signal that all the work is done,
	 * for the benefit of the Parent Thread.
	 */
	pthread_cond_t waiting_cond;
	/* Number of Working Threads. */
	unsigned int working_count;
	/* Number of Worker Threads. */
	unsigned int thread_count;
	/*
	 * Enable to signal all threads to stop.
	 * (But all ongoing tasks will be completed first.)
	 */
	bool stop;
	/*
	 * Tasks registered by the Parent Thread, currently waiting for a
	 * Worker Thread to claim them.
	 */
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

/**
 * Pops the tail of @queue.
 *
 * Freeing the task is the caller's responsibility.
 */
static struct task *
task_queue_pull(struct task_queue *queue)
{
	struct task *tmp;

	tmp = TAILQ_LAST(queue, task_queue);
	TAILQ_REMOVE(queue, tmp, next);
	pr_op_debug("Pulling a task from the pool");

	return tmp;
}

/* Insert the task at the HEAD */
static void
task_queue_push(struct task_queue *queue, struct task *task)
{
	TAILQ_INSERT_HEAD(queue, task, next);
	pr_op_debug("Pushing a task to the pool");
}

/*
 * This is the core Working Thread function.
 *
 * In my opinion, "poll" is a bit of a misnomer. In this context, "poll"
 * appears to mean four things:
 *
 * 1. Wait for work.
 * 2. Claim the work.
 * 3. Do the work.
 * 4. Repeat until someone asks us to stop.
 */
static void *
tasks_poll(void *arg)
{
	struct thread_pool *pool = arg;
	struct task *task;

	while (true) {
		while (TAILQ_EMPTY(&(pool->queue)) && !pool->stop) {
			/* Wait until the parent sends us work. */
			pr_op_debug("Thread waiting for work...");
			pthread_cond_wait(&(pool->working_cond), &(pool->lock));
		}

		if (pool->stop)
			break;

		/* Claim the work. */
		task = task_queue_pull(&(pool->queue));
		pool->working_count++;
		pr_op_debug("Working on task #%u", pool->working_count);
		thread_pool_unlock(pool);

		/*
		 * The null check exists because pthread_cond_signal() is
		 * technically allowed to wake up more than one thread.
		 */
		if (task != NULL) {
			task->cb(task->arg);
			/* Now releasing the task */
			task_destroy(task);
			pr_op_debug("Task ended");
		}

		thread_pool_lock(pool);
		pool->working_count--;

		/* If there's no more work left, signal the parent. */
		if (!pool->stop && pool->working_count == 0 &&
		    TAILQ_EMPTY(&(pool->queue)))
			pthread_cond_signal(&(pool->waiting_cond));
	}

	/* The thread will cease to exist */
	pool->thread_count--;
	pthread_cond_signal(&(pool->waiting_cond));
	thread_pool_unlock(pool);

	return NULL;
}

static int
thread_pool_attr_create(pthread_attr_t *attr)
{
	int error;

	error = pthread_attr_init(attr);
	if (error)
		return pr_op_errno(error, "Calling pthread_attr_init()");

	/* Use 2MB (default in most 64 bits systems) */
	error = pthread_attr_setstacksize(attr, 1024 * 1024 * 2);
	if (error) {
		pthread_attr_destroy(attr);
		return pr_op_errno(error,
		    "Calling pthread_attr_setstacksize()");
	}

	error = pthread_attr_setdetachstate(attr, PTHREAD_CREATE_DETACHED);
	if (error) {
		pthread_attr_destroy(attr);
		return pr_op_errno(error,
		    "Calling pthread_attr_setdetachstate()");
	}

	return 0;
}

static int
spawn_threads(struct thread_pool *pool, unsigned int threads)
{
	pthread_attr_t attr;
	pthread_t thread_id;
	unsigned int i;
	int error;

	error = thread_pool_attr_create(&attr);
	if (error)
		return error;

	for (i = 0; i < threads; i++) {
		memset(&thread_id, 0, sizeof(pthread_t));
		error = pthread_create(&thread_id, &attr, tasks_poll, pool);
		if (error) {
			error = pr_op_errno(error, "Spawning pool thread");
			goto end;
		}

		pool->thread_count++;
		pr_op_debug("Pool thread #%u spawned", i);
	}

end:
	pthread_attr_destroy(&attr);
	return error;
}

int
thread_pool_create(unsigned int threads, struct thread_pool **pool)
{
	struct thread_pool *tmp;
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
	tmp->thread_count = 0;

	error = spawn_threads(tmp, threads);
	if (error)
		goto free_waiting_cond;

	*pool = tmp;
	return 0;
free_waiting_cond:
	pthread_cond_destroy(&(tmp->waiting_cond));
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
	/* There's work to do! */
	pthread_cond_signal(&(pool->working_cond));
	thread_pool_unlock(pool);

	return 0;
}

/* There are available threads to work? */
bool
thread_pool_avail_threads(struct thread_pool *pool)
{
	bool result;

	thread_pool_lock(pool);
	result = (pool->working_count < pool->thread_count);
	thread_pool_unlock(pool);

	return result;
}

/* Waits for all pending tasks at @poll to end */
void
thread_pool_wait(struct thread_pool *pool)
{
	thread_pool_lock(pool);
	while (true) {
		pr_op_debug("Waiting all tasks from the pool to end");
		pr_op_debug("- Stop: %s", pool->stop ? "true" : "false");
		pr_op_debug("- Working count: %u", pool->working_count);
		pr_op_debug("- Thread count: %u", pool->thread_count);
		pr_op_debug("- Empty queue: %s",
		    TAILQ_EMPTY(&(pool->queue)) ? "true" : "false");

		if (pool->stop) {
			/* Wait until all Working Threads are dead. */
			if (pool->thread_count == 0)
				break;
		} else {
			/* Wait until all Working Threads finish. */
			if (pool->working_count == 0 &&
			    TAILQ_EMPTY(&(pool->queue)))
				break;
		}

		pthread_cond_wait(&(pool->waiting_cond), &(pool->lock));
	}
	thread_pool_unlock(pool);
	pr_op_debug("Waiting has ended, all tasks have finished");
}
