#include <check.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "thread/thread_pool.c"

static void
thread_work(void *arg)
{
	int *value = arg;
	(*value) += 2;
}

static void
test_threads_work(unsigned int total_threads)
{
	struct thread_pool *pool;
	int **data;
	int i;
	int error;

	error = thread_pool_create("test pool", total_threads, &pool);
	ck_assert_int_eq(error, 0);

	/* Just a dummy array where each thread will modify one slot only */
	data = calloc(total_threads, sizeof(int *));
	ck_assert_ptr_ne(data, NULL);

	for (i = 0; i < total_threads; i++) {
		data[i] = malloc(sizeof(int));
		ck_assert_ptr_ne(data[i], NULL);
		*data[i] = 0;
		thread_pool_push(pool, "test task", thread_work, data[i]);
	}

	/* Wait for all to finish (~2 sec) */
	thread_pool_wait(pool);

	/* Every element should have been modified */
	for (i = 0; i < total_threads; i++) {
		ck_assert_int_eq(*data[i], 2);
		free(data[i]);
	}

	free(data);
	thread_pool_destroy(pool);
}

START_TEST(tpool_single_work)
{
	test_threads_work(1);
}
END_TEST

START_TEST(tpool_multiple_work)
{
	test_threads_work(200);
}
END_TEST

Suite *thread_pool_suite(void)
{
	Suite *suite;
	TCase *single, *multiple;

	single = tcase_create("single_work");
	tcase_add_test(multiple, tpool_single_work);

	multiple = tcase_create("multiple_work");
	tcase_add_test(multiple, tpool_multiple_work);

	suite = suite_create("thread_pool_test()");
	suite_add_tcase(suite, single);
	suite_add_tcase(suite, multiple);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = thread_pool_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
