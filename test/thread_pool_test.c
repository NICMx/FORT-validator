#include <check.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.c"
#include "impersonator.c"
#include "thread/thread_pool.c"

#define TOTAL_THREADS 50

static void *
thread_work(void *arg)
{
	int *value = arg;
	sleep(2);
	(*value) += 2;
	return NULL;
}

START_TEST(tpool_work)
{
	struct thread_pool *pool;
	int **data;
	int i;
	int error;

	error = thread_pool_create(TOTAL_THREADS, &pool);
	ck_assert_int_eq(error, 0);

	/* Just a dummy array where each thread will modify one slot only */
	data = calloc(TOTAL_THREADS, sizeof(int *));
	ck_assert_ptr_ne(data, NULL);

	for (i = 0; i < TOTAL_THREADS; i++) {
		data[i] = malloc(sizeof(int));
		ck_assert_ptr_ne(data[i], NULL);
		*data[i] = 0;
		thread_pool_push(pool, thread_work, data[i]);
	}

	/* Wait for all to finish (~2 sec) */
	thread_pool_wait(pool);

	/* Every element should have been modified */
	for (i = 0; i < TOTAL_THREADS; i++) {
		ck_assert_int_eq(*data[i], 2);
		free(data[i]);
	}

	free(data);
	thread_pool_destroy(pool);
}
END_TEST

Suite *thread_pool_suite(void)
{
	Suite *suite;
	TCase *work;

	work = tcase_create("work");
	tcase_add_test(work, tpool_work);

	suite = suite_create("thread_pool_test()");
	suite_add_tcase(suite, work);

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
