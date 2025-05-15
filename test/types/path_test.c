#include <check.h>
#include <stdlib.h>

#include "alloc.c"
#include "mock.c"
#include "types/path.c"

#define TEST_JOIN(expected, a, b)				\
	do {							\
		char *actual = path_join(a, b);			\
		ck_assert_pstr_eq(expected, actual);		\
		free(actual);					\
	} while (0);

START_TEST(test_join)
{
	TEST_JOIN("", NULL, NULL);
	TEST_JOIN("", "", NULL);
	TEST_JOIN("", NULL, "");
	TEST_JOIN("", "", "");

	TEST_JOIN("a", "a", NULL);
	TEST_JOIN("b", NULL, "b");
	TEST_JOIN("a/b", "a", "b");
	TEST_JOIN("abcd/efg", "abcd", "efg");

	TEST_JOIN("c/d", "c/", "d");
	TEST_JOIN("e/f", "e", "/f");
	TEST_JOIN("g/h", "g/", "/h");

	TEST_JOIN("/c/d/", "/c/", "d/");
	TEST_JOIN("/e/f/", "/e", "/f/");
	TEST_JOIN("/g/h/", "/g/", "/h/");

	TEST_JOIN("c/d", "c/////", "d");
	TEST_JOIN("e/f", "e", "/////////f");
	TEST_JOIN("g/h", "g///////", "//////h");

	TEST_JOIN("/", "/", "/");
	TEST_JOIN("/", "/", "");
	TEST_JOIN("/", "/", NULL);
	TEST_JOIN("", "", "/");
	TEST_JOIN("", NULL, "/");
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("join");
	tcase_add_test(core, test_join);

	suite = suite_create("path");
	suite_add_tcase(suite, core);
	return suite;
}

int
main(void)
{
	SRunner *runner;
	int failed;

	runner = srunner_create(create_suite());
	srunner_run_all(runner, CK_NORMAL);
	failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
