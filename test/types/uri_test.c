#include <check.h>
#include <stdlib.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "types/path.c"
#include "types/uri.c"

#define TEST_NORMALIZE(dirty, clean)					\
	normal = url_normalize(dirty);					\
	ck_assert_str_eq(clean, normal);				\
	free(normal)

START_TEST(test_normalize)
{
	char *normal;

	TEST_NORMALIZE("rsync://a.b.c", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c/", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c/d", "rsync://a.b.c/d");
	TEST_NORMALIZE("rsync://a.b.c//////", "rsync://a.b.c//////");
	TEST_NORMALIZE("rsync://a.b.c/d/e", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://a.b.c/d/e/.", "rsync://a.b.c/d/e/");
	TEST_NORMALIZE("rsync://a.b.c/d/e/.", "rsync://a.b.c/d/e/");
	TEST_NORMALIZE("rsync://a.b.c/././d/././e/./.", "rsync://a.b.c/d/e/");
	TEST_NORMALIZE("rsync://a.b.c/d/..", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c/x/../x/y/z", "rsync://a.b.c/x/y/z");
	TEST_NORMALIZE("rsync://a.b.c/d/../d/../d/e/", "rsync://a.b.c/d/e/");
	TEST_NORMALIZE("rsync://x//y/z/../../m/./n/o", "rsync://x//m/n/o");

	ck_assert_ptr_eq(NULL, url_normalize(""));
	ck_assert_ptr_eq(NULL, url_normalize("h"));
	ck_assert_ptr_eq(NULL, url_normalize("http"));
	ck_assert_ptr_eq(NULL, url_normalize("https"));
	ck_assert_ptr_eq(NULL, url_normalize("https:"));
	ck_assert_ptr_eq(NULL, url_normalize("https:/"));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://"));
	ck_assert_ptr_eq(NULL, url_normalize("rsync://a.β.c/"));

	TEST_NORMALIZE("rsync://.", "rsync://./");
	TEST_NORMALIZE("https://./.", "https://./");
	TEST_NORMALIZE("https://./d", "https://./d");
	TEST_NORMALIZE("rsync://..", "rsync://../");
	TEST_NORMALIZE("rsync://../..", "rsync://../");
	TEST_NORMALIZE("rsync://../d", "rsync://../d");
	TEST_NORMALIZE("rsync://a.b.c/..", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c/../..", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c/../x", "rsync://a.b.c/x");
	TEST_NORMALIZE("rsync://a.b.c/../x/y/z", "rsync://a.b.c/x/y/z");
	TEST_NORMALIZE("rsync://a.b.c/d/e/../../..", "rsync://a.b.c/");
	ck_assert_ptr_eq(NULL, url_normalize("http://a.b.c/d"));
	ck_assert_ptr_eq(NULL, url_normalize("abcde://a.b.c/d"));
	TEST_NORMALIZE("HTTPS://a.b.c/d", "https://a.b.c/d");
	TEST_NORMALIZE("rSyNc://a.b.c/d", "rsync://a.b.c/d");

	TEST_NORMALIZE("https://a.b.c:80/d/e", "https://a.b.c:80/d/e");
	/* TEST_NORMALIZE("https://a.b.c:443/d/e", "https://a.b.c/d/e"); */
	TEST_NORMALIZE("https://a.b.c:/d/e", "https://a.b.c/d/e");

	/*
	 * XXX make sure libcurl 8.12.2 implements lowercasing domains,
	 * defaulting 443, and maybe reject UTF-8.
	 */
}
END_TEST

#define ck_assert_origin(expected, s1, s2)				\
	do {								\
		__URI_INIT(&u1, s1);					\
		__URI_INIT(&u2, s2);					\
		ck_assert_int_eq(expected, uri_same_origin(&u1, &u2));	\
	} while (0)

START_TEST(test_same_origin)
{
	struct uri u1, u2;

	ck_assert_origin(true,	"https://a.b.c/d/e/f",	"https://a.b.c/g/h/i");
	ck_assert_origin(false,	"https://a.b.cc/d/e/f",	"https://a.b.c/g/h/i");
	ck_assert_origin(false,	"https://a.b.c/d/e/f",	"https://a.b.cc/g/h/i");
	ck_assert_origin(true,	"https://a.b.c",	"https://a.b.c");
	ck_assert_origin(true,	"https://a.b.c/",	"https://a.b.c");
	ck_assert_origin(true,	"https://a.b.c",	"https://a.b.c/");
	ck_assert_origin(true,	"https://",		"https://");
	ck_assert_origin(false,	"https://",		"https://a");
	ck_assert_origin(false,	"https://a",		"https://b");

	/* Undefined, but manhandle the code anyway */
	ck_assert_origin(false,	"",			"");
	ck_assert_origin(false,	"ht",			"ht");
	ck_assert_origin(false,	"https:",		"https:");
	ck_assert_origin(false,	"https:/",		"https:/");
	ck_assert_origin(false,	"https:/a",		"https:/a");
	ck_assert_origin(true,	"https:/a/",		"https:/a/");
}
END_TEST

static Suite *create_suite(void)
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

	suite = create_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
