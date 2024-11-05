#include "task.c"

#include <check.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "types/map.c"
#include "types/path.c"

void
rpki_certificate_free(struct rpki_certificate *cert)
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

	map.url = map.path = mapstr;
	ck_assert_int_eq(1, task_enqueue(&map, &parent));
}

static struct validation_task *
dequeue_1(char *mapstr, struct validation_task *prev)
{
	struct validation_task *task;
	task = task_dequeue(prev);
	ck_assert_str_eq(mapstr, task->ca->map.url);
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
