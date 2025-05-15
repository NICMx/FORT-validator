#include "task.c"

#include <check.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "types/array.h"
#include "types/map.c"
#include "types/uri.c"

void
cer_free(struct rpki_certificate *cert)
{
	if (atomic_fetch_sub(&cert->refcount, 1) == 1) {
		map_cleanup(&cert->map);
		free(cert);
	}
}

static void
queue_1(char *mapstr)
{
	struct cache_mapping map;
	struct rpki_certificate parent = { 0 };

	__URI_INIT(&map.url, mapstr);
	map.path = mapstr;
	ck_assert_int_eq(1, task_enqueue_rpp(&map, &parent));
}

static struct validation_task *
dequeue_1(char *mapstr, struct validation_task *prev)
{
	struct validation_task *task;
	task = task_dequeue(prev);
	ck_assert_uri(mapstr, &task->u.ca->map.url);
	return task;
}

static void
check_empty(struct validation_task *prev)
{
	ck_assert_ptr_eq(NULL, task_dequeue(prev));
}

static void
test_1(char *mapstr)
{
	queue_1(mapstr);
	check_empty(dequeue_1(mapstr, NULL));
}

START_TEST(test_queue_empty)
{
	task_setup();

	task_start();
	ck_assert_ptr_eq(NULL, task_dequeue(NULL));
	ck_assert_ptr_eq(NULL, task_dequeue(NULL));
	task_stop();

	task_teardown();
}
END_TEST

START_TEST(test_queue_1)
{
	task_setup();
	task_start(); test_1("a"); task_stop();
	task_teardown();
}
END_TEST

START_TEST(test_queue_3)
{
	struct validation_task *prev;

	task_setup();
	task_start();

	queue_1("b");
	queue_1("c");
	queue_1("d");

	prev = dequeue_1("b", NULL);
	prev = dequeue_1("c", prev);
	prev = dequeue_1("d", prev);
	check_empty(prev);

	task_stop();
	task_teardown();
}
END_TEST

START_TEST(test_queue_multiple)
{
	task_setup();

	task_start(); test_1("a"); task_stop();
	task_start(); test_1("b"); task_stop();
	task_start(); test_1("c"); task_stop();

	task_teardown();
}
END_TEST

START_TEST(test_queue_interrupted)
{
	struct validation_task *prev;

	task_setup();

	task_start();
	queue_1("1");
	queue_1("2");
	task_stop();

	check_empty(NULL);
	check_empty(NULL);

	task_start();
	check_empty(NULL);
	queue_1("3");
	queue_1("4");
	prev = dequeue_1("3", NULL);
	task_stop();

	check_empty(prev);

	task_teardown();
}
END_TEST

#define TEST_TASKS 3000

struct test_task {
	char id[8];
	STAILQ_ENTRY(test_task) lh;
};

static STAILQ_HEAD(test_task_list, test_task) test_tasks;
static pthread_mutex_t test_tasks_lock = PTHREAD_MUTEX_INITIALIZER;
static bool return_dormant;

static void
populate_test_tasks(void)
{
	struct test_task *task;
	int printed;
	unsigned int i;

	STAILQ_INIT(&test_tasks);
	for (i = 0; i < TEST_TASKS; i++) {
		task = pmalloc(sizeof(struct test_task));
		printed = snprintf(task->id, sizeof(task->id), "%u", i);
		ck_assert_int_gt(printed, 0);
		ck_assert_int_lt(printed, sizeof(task->id));
		STAILQ_INSERT_TAIL(&test_tasks, task, lh);
	}

	printf("+ th-1: Queuing 'starter'\n");
	queue_1("starter");
}

static int
certificate_traverse_mock(struct rpki_certificate *ca, int thid)
{
	struct test_task *new[10];
	unsigned int n;

	/* Queue 10 of the available tasks for each dequeue */

	mutex_lock(&test_tasks_lock);
	for (n = 0; n < 10; n++) {
		new[n] = STAILQ_FIRST(&test_tasks);
		if (new[n])
			STAILQ_REMOVE_HEAD(&test_tasks, lh);
	}
	mutex_unlock(&test_tasks_lock);

	for (n = 0; n < 10; n++) {
		if (!new[n])
			break;
		printf("+ th%d: Queuing '%s'\n", thid, new[n]->id);
		queue_1(new[n]->id);
		free(new[n]);
	}

	if (n != 0)
		task_wakeup();

	if (return_dormant && (rand() & 3) == 0)
		return EBUSY; /* Return "busy" 25% of the time */

	return 0;
}

static void *
user_thread(void *arg)
{
	int thid = *((int *)arg);
	struct validation_task *task = NULL;
	int total_dequeued = 0;

	printf("th%d: Started.\n", thid);

	while ((task = task_dequeue(task)) != NULL) {
		printf("- th%d: Dequeued '%s'\n", thid, uri_str(&task->u.ca->map.url));
		total_dequeued++;

		if (certificate_traverse_mock(task->u.ca, thid) == EBUSY) {
			printf("+ th%d: Requeuing '%s'\n",
			    thid, uri_str(&task->u.ca->map.url));
			task_requeue_dormant(task);
			task = NULL;
		}
	}

	printf("th%d: Dequeued %u times.\n", thid, total_dequeued);
	return NULL;
}

static void
run_threads(void)
{
	pthread_t threads[10];
	int thids[10];
	unsigned int i;

	for (i = 0; i < ARRAY_LEN(threads); i++) {
		thids[i] = i;
		ck_assert_int_eq(0, pthread_create(&threads[i], NULL,
		    user_thread, &thids[i]));
	}

	for (i = 0; i < ARRAY_LEN(threads); i++)
		ck_assert_int_eq(0, pthread_join(threads[i], NULL));

	ck_assert_int_eq(1, STAILQ_EMPTY(&test_tasks));
	ck_assert_ptr_eq(NULL, task_dequeue(NULL));
}

START_TEST(test_queue_multiuser)
{
	return_dormant = false;

	task_setup();
	task_start();

	populate_test_tasks();
	run_threads();

	task_stop();
	task_teardown();
}
END_TEST

static void *
upgrade_dormants(void *arg)
{
	unsigned int i;

	for (i = 0; i < 2; i++) {
		sleep(1);
		printf("Upgrading dormant tasks!\n");
		task_wakeup_dormants();
	}

	sleep(1);
	return_dormant = false;
	printf("Upgrading dormant tasks for the last time!\n");
	task_wakeup_dormants();

	return NULL;
}

START_TEST(test_queue_multiuser_busy)
{
	pthread_t thr;

	return_dormant = true;

	task_setup();
	task_start();

	ck_assert_int_eq(0, pthread_create(&thr, NULL, upgrade_dormants, NULL));

	populate_test_tasks();
	run_threads();

	ck_assert_int_eq(0, pthread_join(thr, NULL));

	task_stop();
	task_teardown();
}
END_TEST

static Suite *create_suite(void)
{
	Suite *suite;
	TCase *queue;

	queue = tcase_create("queue");
	tcase_add_test(queue, test_queue_empty);
	tcase_add_test(queue, test_queue_1);
	tcase_add_test(queue, test_queue_3);
	tcase_add_test(queue, test_queue_multiple);
	tcase_add_test(queue, test_queue_interrupted);
	tcase_add_test(queue, test_queue_multiuser);
	tcase_add_test(queue, test_queue_multiuser_busy);

	suite = suite_create("task");
	suite_add_tcase(suite, queue);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = create_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
