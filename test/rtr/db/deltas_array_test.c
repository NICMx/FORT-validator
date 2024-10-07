#include <check.h>
#include <stdlib.h>

#include "alloc.c"
#include "mock.c"
#include "types/address.c"
#include "types/delta.c"
#include "types/router_key.c"
#include "types/vrp.c"
#include "rtr/db/delta.c"
#include "rtr/db/deltas_array.c"

#define TOTAL_CREATED 15
static struct deltas *created[TOTAL_CREATED];

MOCK_UINT(config_get_deltas_lifetime, 5, void)

static int
foreach_cb(struct deltas *deltas, void *arg)
{
	unsigned int *next_index = arg;

	ck_assert_ptr_eq(created[*next_index], deltas);
	(*next_index)++;

	return 0;
}

static void
test_foreach(struct deltas_array *darray, unsigned int total,
    unsigned int offset)
{
	unsigned int next_index;
	unsigned int i;

	for (i = 0; i <= total; i++) {
		next_index = total - i + offset;
		ck_assert_int_eq(0, darray_foreach_since(darray, i,
		    foreach_cb, &next_index));
		ck_assert_uint_eq(total + offset, next_index);
	}

	ck_assert_int_eq(-EINVAL, darray_foreach_since(darray, total + 1,
	    foreach_cb, &next_index));
}

START_TEST(add_only)
{
	struct deltas_array *darray;
	unsigned int i;

	darray = darray_create();
	ck_assert_ptr_ne(NULL, darray);

	for (i = 0; i < TOTAL_CREATED; i++) {
		created[i] = deltas_create();
		ck_assert_ptr_ne(NULL, created[i]);
	}

	test_foreach(darray, 0, 0);

	darray_add(darray, created[0]);
	test_foreach(darray, 1, 0);

	darray_add(darray, created[1]);
	test_foreach(darray, 2, 0);

	darray_add(darray, created[2]);
	test_foreach(darray, 3, 0);

	darray_add(darray, created[3]);
	test_foreach(darray, 4, 0);

	for (i = 4; i < TOTAL_CREATED; i++) {
		darray_add(darray, created[i]);
		test_foreach(darray, 5, i - 4);
	}
}
END_TEST

static Suite *create_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, add_only);

	suite = suite_create("Deltas Array");
	suite_add_tcase(suite, core);
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
