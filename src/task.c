#include "task.h"

#include <errno.h>

#include "alloc.h"
#include "common.h"
#include "log.h"

STAILQ_HEAD(validation_tasks, validation_task);

/* Queued, not yet claimed tasks */
static struct validation_tasks tasks;
/* Queued, but not yet available for claiming */
static struct validation_tasks busy;
/* Active tasks (length(@tasks) + length(@busy) + number of running tasks) */
static int active;

static bool enabled = true;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t awakener = PTHREAD_COND_INITIALIZER;

static void
task_free(struct validation_task *task)
{
	rpki_certificate_free(task->ca);
	free(task);
}

void
task_setup(void)
{
	STAILQ_INIT(&tasks);
	STAILQ_INIT(&busy);
	active = 0;
	enabled = true;
	panic_on_fail(pthread_mutex_init(&lock, NULL), "pthread_mutex_init");
	panic_on_fail(pthread_cond_init(&awakener, NULL), "pthread_cond_init");
}

static void
cleanup_tasks(struct validation_tasks *tasks)
{
	struct validation_task *task;

	while (!STAILQ_EMPTY(tasks)) {
		task = STAILQ_FIRST(tasks);
		STAILQ_REMOVE_HEAD(tasks, lh);
		task_free(task);
	}
}

static void
cleanup(void)
{
	enabled = false;
	active = 0;
	cleanup_tasks(&tasks);
	cleanup_tasks(&busy);
}

void
task_start(void)
{
	cleanup();
	enabled = true;
}

void
task_stop(void)
{
	mutex_lock(&lock);
	cleanup();
	mutex_unlock(&lock);
}

void
task_teardown(void)
{
	pthread_mutex_destroy(&lock);
	pthread_cond_destroy(&awakener);
}

/*
 * Defers a task for later.
 * Call task_wakeup() once you've queued all your tasks.
 */
unsigned int
task_enqueue(struct cache_mapping *map, struct rpki_certificate *parent)
{
	struct validation_task *task;
	struct rpki_certificate *ca;

	atomic_fetch_add(&parent->refcount, 1);

	ca = pzalloc(sizeof(struct rpki_certificate));
	ca->map.url = pstrdup(map->url);
	ca->map.path = pstrdup(map->path);
	ca->parent = parent;
	atomic_init(&ca->refcount, 1);

	task = pmalloc(sizeof(struct validation_task));
	task->ca = ca;

	mutex_lock(&lock);
	if (enabled) {
		STAILQ_INSERT_TAIL(&tasks, task, lh);
		task = NULL;
		active++;
	}
	mutex_unlock(&lock);

	if (task) {
		task_free(task); /* Couldn't queue */
		return 0;
	}

	return 1;
}

void
task_requeue_busy(struct validation_task *task)
{
	mutex_lock(&lock);
	if (enabled) {
		STAILQ_INSERT_TAIL(&busy, task, lh);
		task = NULL;
	}
	mutex_unlock(&lock);

	if (task)
		task_free(task); /* Couldn't queue */
}

/* Wakes up threads currently waiting for tasks. */
void
task_wakeup(void)
{
	mutex_lock(&lock);
	panic_on_fail(pthread_cond_broadcast(&awakener),
	    "pthread_cond_broadcast");
	mutex_unlock(&lock);
}

void
task_wakeup_busy(void)
{
	mutex_lock(&lock);
	STAILQ_CONCAT(&tasks, &busy);
	panic_on_fail(pthread_cond_broadcast(&awakener),
	    "pthread_cond_broadcast");
	mutex_unlock(&lock);
}

/*
 * Frees the @prev previous task, and returns the next one.
 *
 * If no task is available yet, will sleep until someone calls task_wakeup() or
 * task_wakeup_busy().
 * If all the tasks are done, returns NULL.
 *
 * Assumes at least one task has been queued before the first dequeue.
 */
struct validation_task *
task_dequeue(struct validation_task *prev)
{
	struct validation_task *task;
	struct timespec timeout;
	int error;

	if (prev)
		task_free(prev);
	timeout.tv_nsec = 0;

	mutex_lock(&lock);

	if (!enabled)
		goto end;

	if (prev) {
		active--;
		if (active < 0)
			pr_crit("active < 0: %d", active);
	}

	while (active > 0) {
		pr_op_debug("task_dequeue(): %u tasks active.", active);

		task = STAILQ_FIRST(&tasks);
		if (task != NULL) {
			STAILQ_REMOVE_HEAD(&tasks, lh);
			mutex_unlock(&lock);
			pr_op_debug("task_dequeue(): Claimed task '%s'.",
			    task->ca->map.url);
			return task;
		}

		pr_op_debug("task_dequeue(): Sleeping...");
		timeout.tv_sec = time_fatal() + 10;
		error = pthread_cond_timedwait(&awakener, &lock, &timeout);
		switch (error) {
		case 0:
			pr_op_debug("task_dequeue(): Woke up by cond.");
			break;
		case ETIMEDOUT:
			pr_op_debug("task_dequeue(): Woke up by timeout.");
			break;
		case EINTR:
			pr_op_debug("task_dequeue(): Interrupted by signal.");
			goto end;
		default:
			panic_on_fail(error, "pthread_cond_wait");
		}
	}

	pr_op_debug("task_dequeue(): No more tasks; done.");
	panic_on_fail(pthread_cond_broadcast(&awakener),
	    "pthread_cond_broadcast");
end:	mutex_unlock(&lock);
	return NULL;
}