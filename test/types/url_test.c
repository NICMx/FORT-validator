#include <check.h>
#include <stdlib.h>

#include "alloc.c"
#include "mock.c"
#include "types/path.c"
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
	TEST_NORMALIZE("rsync://a.b.c/x/../x/y/z", "rsync://a.b.c/x/y/z");
	TEST_NORMALIZE("rsync://a.b.c/d/../d/../d/e/", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://x//y/z/../../m/./n/o", "rsync://x/m/n/o");
	ck_assert_ptr_eq(NULL, url_normalize("rsync://"));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://."));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://.."));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://a.b.c/.."));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://a.b.c/../x"));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://a.b.c/../x/y/z"));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://a.b.c/d/e/../../.."));
	ck_assert_ptr_eq(NULL, url_normalize("abcde://a.b.c/d"));
}
END_TEST

START_TEST(test_same_origin)
{
	ck_assert_int_eq(true,	url_same_origin("https://a.b.c/d/e/f",	"https://a.b.c/g/h/i"));
	ck_assert_int_eq(false,	url_same_origin("https://a.b.cc/d/e/f",	"https://a.b.c/g/h/i"));
	ck_assert_int_eq(false,	url_same_origin("https://a.b.c/d/e/f",	"https://a.b.cc/g/h/i"));
	ck_assert_int_eq(true,	url_same_origin("https://a.b.c",	"https://a.b.c"));
	ck_assert_int_eq(true,	url_same_origin("https://a.b.c/",	"https://a.b.c"));
	ck_assert_int_eq(true,	url_same_origin("https://a.b.c",	"https://a.b.c/"));
	ck_assert_int_eq(true,	url_same_origin("https://",		"https://"));
	ck_assert_int_eq(false,	url_same_origin("https://",		"https://a"));
	ck_assert_int_eq(false,	url_same_origin("https://a",		"https://b"));

	/* Undefined, but manhandle the code anyway */
	ck_assert_int_eq(false,	url_same_origin("",			""));
	ck_assert_int_eq(false,	url_same_origin("ht",			"ht"));
	ck_assert_int_eq(false,	url_same_origin("https:",		"https:"));
	ck_assert_int_eq(false,	url_same_origin("https:/",		"https:/"));
	ck_assert_int_eq(false,	url_same_origin("https:/a",		"https:/a"));
	ck_assert_int_eq(true,	url_same_origin("https:/a/",		"https:/a/"));
}
END_TEST

static Suite *thread_pool_suite(void)
{
	Suite *suite;
	TCase *misc;

	misc = tcase_create("misc");
	tcase_add_test(misc, test_normalize);
	tcase_add_test(misc, test_same_origin);

	suite = suite_create("url");
	suite_add_tcase(suite, misc);

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
