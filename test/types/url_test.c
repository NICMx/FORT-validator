#include <check.h>
#include <stdlib.h>

#include "alloc.c"
#include "mock.c"
#include "data_structure/path_builder.c"
#include "types/url.c"

#define TEST_NORMALIZE(dirty, clean)					\
	normal = url_normalize(dirty);					\
	ck_assert_str_eq(clean, normal);				\
	free(normal)

START_TEST(test_normalize)
{
	char *normal;

	TEST_NORMALIZE("rsync://a.b.c", "rsync://a.b.c");
	TEST_NORMALIZE("rsync://a.b.c/", "rsync://a.b.c");
	TEST_NORMALIZE("rsync://a.b.c//////", "rsync://a.b.c");
	TEST_NORMALIZE("rsync://a.b.c/d/e", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://a.b.c/d/e/.", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://a.b.c/d/e/.", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://a.b.c/d/./e/.", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://a.b.c/d/../d/../d/e/", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://a.b.c/../x/y/z", "rsync://x/y/z");
	TEST_NORMALIZE("rsync://x//y/z/../../../m/./n/o", "rsync://m/n/o");
	ck_assert_ptr_eq(NULL, url_normalize("rsync://"));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://.."));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://a.b.c/.."));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://a.b.c/d/e/../../.."));
	ck_assert_ptr_eq(NULL, url_normalize("abcde://a.b.c/d"));
}
END_TEST

static Suite *thread_pool_suite(void)
{
	Suite *suite;
	TCase *normalize;

	normalize = tcase_create("normalize");
	tcase_add_test(normalize, test_normalize);

	suite = suite_create("url");
	suite_add_tcase(suite, normalize);

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
