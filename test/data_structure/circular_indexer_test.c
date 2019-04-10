#include "data_structure/circular_indexer.h"

#include <check.h>
#include <errno.h>
#include <stdlib.h>

/*
 * These are macros so CHECK will be able to report proper lines on errors.
 * Functions would ruin that.
 */

static array_index *tmp;
#define assert_index(expected, actual)					\
	tmp = actual;							\
	ck_assert_ptr_ne(NULL, tmp);					\
	ck_assert_int_eq(expected, *tmp);

#define assert_next_is_null(indexer)					\
	/* Twice, to make sure it stays consistent. */			\
	ck_assert_ptr_eq(NULL, arridx_next(indexer));			\
	ck_assert_ptr_eq(NULL, arridx_next(indexer));

#define assert_first_is_null(indexer)					\
	ck_assert_ptr_eq(NULL, arridx_first(indexer));			\
	ck_assert_ptr_eq(NULL, arridx_first(indexer));

START_TEST(no_removes)
{
	struct circular_indexer indexer;

	arridx_init(&indexer, 4);

	/* Full traversal from 0 */
	assert_index(0, arridx_first(&indexer));
	assert_index(1, arridx_next(&indexer));
	assert_index(2, arridx_next(&indexer));
	assert_index(3, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	assert_index(0, arridx_first(&indexer));
	assert_index(1, arridx_next(&indexer));
	assert_index(2, arridx_next(&indexer));

	/* Full traversal from 3 */
	assert_index(3, arridx_first(&indexer));
	assert_index(0, arridx_next(&indexer));
	assert_index(1, arridx_next(&indexer));
	assert_index(2, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	assert_index(3, arridx_first(&indexer));
	assert_index(0, arridx_next(&indexer));
	assert_index(1, arridx_next(&indexer));

	/* Full traversal from 2 */
	assert_index(2, arridx_first(&indexer));
	assert_index(3, arridx_next(&indexer));
	assert_index(0, arridx_next(&indexer));
	assert_index(1, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	assert_index(2, arridx_first(&indexer));
	assert_index(3, arridx_next(&indexer));
	assert_index(0, arridx_next(&indexer));

	/* Full traversal from 1 */
	assert_index(1, arridx_first(&indexer));
	assert_index(2, arridx_next(&indexer));
	assert_index(3, arridx_next(&indexer));
	assert_index(0, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	ck_assert_ptr_eq(NULL, indexer.indexes);
	arridx_cleanup(&indexer);
}
END_TEST

static void
test_traversal_with_removal(array_index *(*traverser)(struct circular_indexer *))
{
	struct circular_indexer indexer;

	arridx_init(&indexer, 5);

	assert_index(0, arridx_first(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(1, traverser(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(2, traverser(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(3, traverser(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(4, traverser(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));

	assert_next_is_null(&indexer);
	assert_first_is_null(&indexer);
	assert_next_is_null(&indexer);

	ck_assert_ptr_eq(NULL, indexer.indexes);
	arridx_cleanup(&indexer);
}

START_TEST(always_remove_first)
{
	test_traversal_with_removal(arridx_first);
}
END_TEST

START_TEST(always_remove_next)
{
	test_traversal_with_removal(arridx_next);
}
END_TEST

START_TEST(remove_only_top)
{
	/* This one is also unnecessary. */

	struct circular_indexer indexer;

	arridx_init(&indexer, 5);

	/* 0 1 2 3 4 */
	assert_index(0, arridx_first(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(1, arridx_next(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(2, arridx_next(&indexer));
	assert_index(3, arridx_next(&indexer));
	assert_index(4, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	/* 2 3 4 (just make sure the indexer was left in a consistent state) */
	assert_index(2, arridx_first(&indexer));
	assert_index(3, arridx_next(&indexer));
	assert_index(4, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	/* 2 3 4 */
	assert_index(2, arridx_first(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(3, arridx_next(&indexer));
	assert_index(4, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	/* 3 4 */
	assert_index(3, arridx_first(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(4, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	/* 4 */
	assert_index(4, arridx_first(&indexer));
	assert_next_is_null(&indexer);

	/* 4 */
	assert_index(4, arridx_first(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_next_is_null(&indexer);

	/* */
	assert_first_is_null(&indexer);
	assert_next_is_null(&indexer);

	ck_assert_ptr_eq(NULL, indexer.indexes);
	arridx_cleanup(&indexer);
}
END_TEST

START_TEST(remove_top_mid_iteration)
{
	struct circular_indexer indexer;

	arridx_init(&indexer, 4);

	/* 0 1 2 3 */
	assert_index(0, arridx_first(&indexer));
	assert_index(1, arridx_next(&indexer));
	assert_index(2, arridx_next(&indexer));

	/* 3 0 1 2 */
	assert_index(3, arridx_first(&indexer));
	assert_index(0, arridx_next(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(1, arridx_next(&indexer));
	assert_index(2, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	/* 3 1 2 */
	assert_index(3, arridx_first(&indexer));
	assert_index(1, arridx_next(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(2, arridx_next(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_next_is_null(&indexer);

	/* 3 */
	assert_index(3, arridx_first(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_next_is_null(&indexer);

	/* */
	assert_first_is_null(&indexer);
	assert_next_is_null(&indexer);

	ck_assert_ptr_eq(NULL, indexer.indexes);
	arridx_cleanup(&indexer);
}
END_TEST

static void
traverse_mallocd_indexer_easy(array_index *(*traverser)(struct circular_indexer *))
{
	struct circular_indexer indexer;

	arridx_init(&indexer, 4);

	/* (This iteration is mostly just intended to prepare the array) */
	/* 0 1 2 3 */
	assert_index(0, arridx_first(&indexer));
	assert_index(1, arridx_next(&indexer));

	ck_assert_ptr_eq(NULL, indexer.indexes);
	ck_assert_int_eq(0, arridx_remove(&indexer));
	ck_assert_ptr_ne(NULL, indexer.indexes);

	assert_index(2, arridx_next(&indexer));
	assert_index(3, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	/* (This is the actual test) */
	/* 0 2 3 */
	assert_index(0, arridx_first(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(2, traverser(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(3, traverser(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_next_is_null(&indexer);

	/* */
	assert_first_is_null(&indexer);
	assert_next_is_null(&indexer);

	arridx_cleanup(&indexer);
}

START_TEST(malloc_always_remove_first_simple)
{
	traverse_mallocd_indexer_easy(arridx_first);
}
END_TEST

START_TEST(malloc_always_remove_next_simple)
{
	traverse_mallocd_indexer_easy(arridx_next);
}
END_TEST

/*
 * This is the same as traverse_mallocd_indexer(), except it has the first, last
 * and two contiguous elements pre-removed, cuz that's trickier.
 */
static void
traverse_mallocd_indexer_hard(array_index *(*traverser)(struct circular_indexer *))
{
	struct circular_indexer indexer;

	arridx_init(&indexer, 8);

	/* -- Prepare the array -- */
	/*
	 * Despite being initialization, this actually manhandles the indexer
	 * quite a bit, which is good.
	 */
	/* 0 1 2 3 4 5 6 7 */
	assert_index(0, arridx_first(&indexer));
	assert_index(1, arridx_next(&indexer));
	assert_index(2, arridx_next(&indexer));

	assert_index(3, arridx_next(&indexer));
	ck_assert_ptr_eq(NULL, indexer.indexes);
	ck_assert_int_eq(0, arridx_remove(&indexer));
	ck_assert_ptr_ne(NULL, indexer.indexes);

	assert_index(4, arridx_next(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));

	assert_index(5, arridx_next(&indexer));
	assert_index(6, arridx_next(&indexer));

	assert_index(7, arridx_next(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));

	assert_next_is_null(&indexer);

	/* 0 1 2 5 6 */
	assert_index(0, arridx_first(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));

	/* -- Actual test -- */
	/* Let's do an innocent traversal first, just for shits and giggles. */
	/* 1 2 5 6 */
	assert_index(1, arridx_first(&indexer));
	assert_index(2, arridx_next(&indexer));
	assert_index(5, arridx_next(&indexer));
	assert_index(6, arridx_next(&indexer));
	assert_next_is_null(&indexer);

	/* Ok, begin. */
	/* 1 2 5 6 */
	assert_index(1, arridx_first(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(2, traverser(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(5, traverser(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_index(6, traverser(&indexer));
	ck_assert_int_eq(0, arridx_remove(&indexer));
	assert_next_is_null(&indexer);

	/* */
	assert_first_is_null(&indexer);
	assert_next_is_null(&indexer);

	arridx_cleanup(&indexer);
}

START_TEST(malloc_always_remove_first_complex)
{
	traverse_mallocd_indexer_hard(arridx_first);
}
END_TEST

START_TEST(malloc_always_remove_next_complex)
{
	traverse_mallocd_indexer_hard(arridx_next);
}
END_TEST

Suite *address_load_suite(void)
{
	Suite *suite;
	TCase *malloc_no;
	TCase *malloc_yes;

	/* Tests in which the indexer.indexes array is not allocated. */
	malloc_no = tcase_create("No malloc tests");
	tcase_add_test(malloc_no, no_removes);
	tcase_add_test(malloc_no, always_remove_first);
	tcase_add_test(malloc_no, always_remove_next);
	tcase_add_test(malloc_no, remove_only_top);
	tcase_add_test(malloc_no, remove_top_mid_iteration);

	/* Tests that involve the indexer.indexes array. */
	malloc_yes = tcase_create("malloc tests");
	tcase_add_test(malloc_yes, malloc_always_remove_first_simple);
	tcase_add_test(malloc_yes, malloc_always_remove_next_simple);
	tcase_add_test(malloc_yes, malloc_always_remove_first_complex);
	tcase_add_test(malloc_yes, malloc_always_remove_next_complex);

	suite = suite_create("Circular indexer");
	suite_add_tcase(suite, malloc_no);
	suite_add_tcase(suite, malloc_yes);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = address_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
