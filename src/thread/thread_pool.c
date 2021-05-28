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
struct thread_pool_task {
	/*
	 * Debugging purposes only. Uniqueness is not a requirement.
	 * Will not be released by task_destroy().
	 */
	char const *name;
	thread_pool_task_cb cb;
	void *arg;
	TAILQ_ENTRY(thread_pool_task) next;
};

/* A collection of Tasks, used as FIFO. */
TAILQ_HEAD(task_queue, thread_pool_task);

struct thread_pool {
	/*
	 * Debugging purposes only. Uniqueness is not a requirement.
	 * Will not be released by thread_pool_destroy().
	 */
	char const *name;
	pthread_mutex_t lock;
	/*
	 * Used by the Parent Thread to wake up Worker Threads when there's
	 * work.
	 */
	pthread_cond_t parent2worker;
	/*
	 * Used by Working Threads to signal the Parent Thread that workers are
	 * ready (during initialization) or that all the work is done (after
	 * initialization).
	 */
	pthread_cond_t worker2parent;
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
panic_on_fail(int error, char const *function_name)
{
	if (error)
		pr_crit("%s() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    function_name, error);
}

static void
mutex_lock(struct thread_pool *pool)
{
	panic_on_fail(pthread_mutex_lock(&pool->lock), "pthread_mutex_lock");
}

static void
mutex_unlock(struct thread_pool *pool)
{
	panic_on_fail(pthread_mutex_unlock(&pool->lock), "pthread_mutex_unlock");
}

/* Wait until the parent sends us work. */
static void
wait_for_parent_signal(struct thread_pool *pool, unsigned int thread_id)
{
	pr_op_debug("Thread %s.%u: Waiting for work...", pool->name, thread_id);
	panic_on_fail(pthread_cond_wait(&pool->parent2worker, &pool->lock),
	    "pthread_cond_wait");
}

static void
signal_to_parent(struct thread_pool *pool)
{
	panic_on_fail(pthread_cond_signal(&pool->worker2parent),
	    "pthread_cond_signal");
}

static void
wait_for_worker_signal(struct thread_pool *pool)
{
	panic_on_fail(pthread_cond_wait(&pool->worker2parent, &pool->lock),
	    "pthread_cond_wait");
}

static void
signal_to_worker(struct thread_pool *pool)
{
	panic_on_fail(pthread_cond_signal(&pool->parent2worker),
	    "pthread_cond_signal");
}

static int
task_create(char const *name, thread_pool_task_cb cb, void *arg,
    struct thread_pool_task **out)
{
	struct thread_pool_task *task;

	task = malloc(sizeof(struct thread_pool_task));
	if (task == NULL)
		return pr_enomem();

	task->name = name;
	task->cb = cb;
	task->arg = arg;

	*out = task;
	return 0;
}

static void
task_destroy(struct thread_pool_task *task)
{
	free(task);
}

/**
 * Pops the tail of @queue. pthread_cond_signal() is technically allowed to wake
 * more than one thread, so please keep in mind that the result might be NULL.
 *
 * Freeing the task is the caller's responsibility.
 */
static struct thread_pool_task *
task_queue_pull(struct thread_pool *pool, unsigned int thread_id)
{
	struct thread_pool_task *task;

	task = TAILQ_LAST(&pool->queue, task_queue);
	if (task != NULL) {
		TAILQ_REMOVE(&pool->queue, task, next);
		pr_op_debug("Thread %s.%u: Claimed task '%s'", pool->name,
		    thread_id, task->name);
	} else {
		pr_op_debug("Thread %s.%u: Claimed nothing", pool->name,
		    thread_id);
	}

	return task;
}

/* Insert the task at the HEAD */
static void
task_queue_push(struct thread_pool *pool, struct thread_pool_task *task)
{
	TAILQ_INSERT_HEAD(&pool->queue, task, next);
	pr_op_debug("Pool '%s': Pushed task '%s'", pool->name, task->name);
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
	struct thread_pool_task *task;
	unsigned int thread_id;

	mutex_lock(pool);
	thread_id = pool->thread_count;

	/* We're running; signal the Parent Thread. */
	pool->thread_count++;
	if (pool->thread_count == 1)
		signal_to_parent(pool);

	while (true) {
		while (TAILQ_EMPTY(&pool->queue) && !pool->stop)
			wait_for_parent_signal(pool, thread_id);

		if (pool->stop)
			break;

		/* Claim the work. */
		task = task_queue_pull(pool, thread_id);
		pool->working_count++;
		mutex_unlock(pool);

		if (task != NULL) {
			PR_DEBUG;
			task->cb(task->arg);
			pr_op_debug("Thread %s.%u: Task '%s' ended", pool->name,
			    thread_id, task->name);
			task_destroy(task);
		}

		mutex_lock(pool);
		pool->working_count--;

		if (pool->stop)
			break;
		/* If there's no more work left, wake up parent. */
		if (pool->working_count == 0 && TAILQ_EMPTY(&pool->queue))
			signal_to_parent(pool);
	}

	/* The thread will cease to exist */
	pool->thread_count--;
	if (pool->thread_count == 0)
		signal_to_parent(pool);
	mutex_unlock(pool);

	pr_op_debug("Thread %s.%u: Terminating.", pool->name, thread_id);
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

		pr_op_debug("Pool '%s': Thread #%u spawned", pool->name, i);
	}

end:
	pthread_attr_destroy(&attr);
	return error;
}

int
thread_pool_create(char const *name, unsigned int threads,
    struct thread_pool **pool)
{
	struct thread_pool *result;
	int error;

	result = malloc(sizeof(struct thread_pool));
	if (result == NULL)
		return pr_enomem();

	/* Init locking */
	error = pthread_mutex_init(&result->lock, NULL);
	if (error) {
		error = pr_op_errno(error, "Calling pthread_mutex_init()");
		goto free_tmp;
	}

	/* Init conditional to signal pending work */
	error = pthread_cond_init(&result->parent2worker, NULL);
	if (error) {
		error = pr_op_errno(error,
		    "Calling pthread_cond_init() at working condition");
		goto free_mutex;
	}

	/* Init conditional to signal no pending work */
	error = pthread_cond_init(&result->worker2parent, NULL);
	if (error) {
		error = pr_op_errno(error,
		    "Calling pthread_cond_init() at waiting condition");
		goto free_working_cond;
	}

	TAILQ_INIT(&result->queue);
	result->name = name;
	result->stop = false;
	result->working_count = 0;
	result->thread_count = 0;

	error = spawn_threads(result, threads);
	if (error)
		goto free_waiting_cond;

	*pool = result;
	return 0;
free_waiting_cond:
	pthread_cond_destroy(&result->worker2parent);
free_working_cond:
	pthread_cond_destroy(&result->parent2worker);
free_mutex:
	pthread_mutex_destroy(&result->lock);
free_tmp:
	free(result);
	return error;
}

void
thread_pool_destroy(struct thread_pool *pool)
{
	struct task_queue *queue;
	struct thread_pool_task *tmp;

	/* Remove all pending work and send the signal to stop it */
	mutex_lock(pool);
	queue = &(pool->queue);
	while (!TAILQ_EMPTY(queue)) {
		tmp = TAILQ_FIRST(queue);
		TAILQ_REMOVE(queue, tmp, next);
		task_destroy(tmp);
	}
	pool->stop = true;
	pthread_cond_broadcast(&pool->parent2worker);
	mutex_unlock(pool);

	/* Wait for all to end */
	thread_pool_wait(pool);

	pthread_cond_destroy(&pool->worker2parent);
	pthread_cond_destroy(&pool->parent2worker);
	pthread_mutex_destroy(&pool->lock);
	free(pool);
}

/*
 * pthread_create() does not guarantee that the threads will have started by the
 * time work needs to be done.
 *
 * If they haven't started, this function will add a little timeout.
 *
 * Lock must be held.
 */
static int validate_thread_count(struct thread_pool *pool)
{
	struct timespec tmout;
	int error;

	if (pool->thread_count != 0)
		return 0;

	/* Give the threads 2 more seconds */
	clock_gettime(CLOCK_REALTIME, &tmout);
	tmout.tv_sec += 2;
	error = pthread_cond_timedwait(&pool->worker2parent, &pool->lock,
	    &tmout);

	if (pool->thread_count != 0)
		return 0;

	return pr_op_errno(error, "Waiting thread to start");
}

/*
 * Push a new task to @pool, the task to be executed is @cb with the argument
 * @arg.
 */
int
thread_pool_push(struct thread_pool *pool, char const *task_name,
    thread_pool_task_cb cb, void *arg)
{
	struct thread_pool_task *task;
	int error;

	error = task_create(task_name, cb, arg, &task);
	if (error)
		return error;

	mutex_lock(pool);

	error = validate_thread_count(pool);
	if (error) {
		mutex_unlock(pool);
		task_destroy(task);
		return error;
	}

	task_queue_push(pool, task);
	mutex_unlock(pool);
	signal_to_worker(pool);
	return 0;
}

/* There are available threads to work? */
bool
thread_pool_avail_threads(struct thread_pool *pool)
{
	bool result;

	mutex_lock(pool);
	result = (pool->working_count < pool->thread_count);
	mutex_unlock(pool);

	return result;
}

/* Waits for all pending tasks at @poll to end */
void
thread_pool_wait(struct thread_pool *pool)
{
	mutex_lock(pool);

	while (true) {
		pr_op_debug("- Stop: %s", pool->stop ? "true" : "false");
		pr_op_debug("- Working count: %u", pool->working_count);
		pr_op_debug("- Thread count: %u", pool->thread_count);
		pr_op_debug("- Empty task queue: %s",
		    TAILQ_EMPTY(&pool->queue) ? "true" : "false");

		if (pool->stop) {
			/* Wait until all Working Threads are dead. */
			if (pool->thread_count == 0)
				break;
		} else {
			/* Wait until all Working Threads finish. */
			if (pool->working_count == 0 &&
			    TAILQ_EMPTY(&pool->queue))
				break;
		}

		pr_op_debug("Pool '%s': Waiting for tasks to be completed",
		    pool->name);
		wait_for_worker_signal(pool);
	}

	mutex_unlock(pool);
	pr_op_debug("Pool '%s': Waiting has ended, all tasks done", pool->name);
}
