#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "log.c"
#include "impersonator.c"
#include "str.c"
#include "uri.c"
#include "rsync/rsync.c"

START_TEST(rsync_load_normal)
{

}
END_TEST

static void
assert_descendant(bool expected, char *ancestor, char *descendant)
{
	struct rpki_uri *ancestor_uri;
	struct rpki_uri *descendant_uri;

	ck_assert_int_eq(0, uri_create_str(&ancestor_uri, ancestor,
	    strlen(ancestor)));
	ck_assert_int_eq(0, uri_create_str(&descendant_uri, descendant,
	    strlen(descendant)));

	ck_assert_int_eq(is_descendant(ancestor_uri, descendant_uri), expected);

	uri_refput(ancestor_uri);
	uri_refput(descendant_uri);
}

START_TEST(rsync_test_prefix_equals)
{
	char *ancestor;

	ancestor = "rsync://a/b/c";
	assert_descendant(true, ancestor, "rsync://a/b/c");
	assert_descendant(false, ancestor, "rsync://a/b/");
	assert_descendant(true, ancestor, "rsync://a/b/c/c");
	assert_descendant(false, ancestor, "rsync://a/b/cc");
	assert_descendant(false, ancestor, "rsync://a/b/cc/");

	ancestor = "rsync://a/b/c/";
	assert_descendant(true, ancestor, "rsync://a/b/c");
	assert_descendant(false, ancestor, "rsync://a/b/");
	assert_descendant(true, ancestor, "rsync://a/b/c/c");
	assert_descendant(false, ancestor, "rsync://a/b/cc");
	assert_descendant(false, ancestor, "rsync://a/b/cc/");
}
END_TEST

static void
__mark_as_downloaded(char *uri_str)
{
	struct rpki_uri *uri;
	ck_assert_int_eq(0, uri_create_str(&uri, uri_str, strlen(uri_str)));
	ck_assert_int_eq(mark_as_downloaded(uri), 0);
	uri_refput(uri);
}

static void
assert_downloaded(char *uri_str, bool expected)
{
	struct rpki_uri *uri;
	ck_assert_int_eq(0, uri_create_str(&uri, uri_str, strlen(uri_str)));
	ck_assert_int_eq(is_already_downloaded(uri), expected);
	uri_refput(uri);
}

START_TEST(rsync_test_list)
{
	struct uri *uri;

	ck_assert_int_eq(rsync_init(), 0);

	__mark_as_downloaded("rsync://example.foo/repository/");
	__mark_as_downloaded("rsync://example.foo/member_repository/");
	__mark_as_downloaded("rsync://example.foz/repository/");
	__mark_as_downloaded("rsync://example.boo/repo/");
	__mark_as_downloaded("rsync://example.potato/rpki/");

	assert_downloaded("rsync://example.foo/repository/", true);
	assert_downloaded("rsync://example.foo/repository/abc/cdfg", true);
	assert_downloaded("rsync://example.foo/member_repository/bca", true);
	assert_downloaded("rsync://example.boo/repository/", false);
	assert_downloaded("rsync://example.potato/repository/", false);
	assert_downloaded("rsync://example.potato/rpki/abc/", true);

	/* rsync destroy */
	while (!SLIST_EMPTY(&visited_uris)) {
		uri = SLIST_FIRST(&visited_uris);
		SLIST_REMOVE_HEAD(&visited_uris, next);
		free(uri);
	}
}
END_TEST

static void
test_root_strategy(char *test, char *expected)
{
	struct rpki_uri *src;
	struct rpki_uri *dst;

	ck_assert_int_eq(0, uri_create_str(&src, test, strlen(test)));
	ck_assert_int_eq(handle_root_strategy(src, &dst), 0);
	ck_assert_str_eq(uri_get_global(dst), expected);

	uri_refput(src);
	uri_refput(dst);
}

START_TEST(rsync_test_get_prefix)
{
	test_root_strategy("rsync://www.example1.com/test/foo/",
	    "rsync://www.example1.com/test");
	test_root_strategy("rsync://www.example1.com/test/foo/bar",
	    "rsync://www.example1.com/test");
	test_root_strategy("rsync://www.example1.com/test/",
	    "rsync://www.example1.com/test");
	test_root_strategy("rsync://www.example1.com/test",
	    "rsync://www.example1.com/test");
	test_root_strategy("rsync://www.example1.com",
	    "rsync://www.example1.com");
	test_root_strategy("rsync://w", "rsync://w");
	test_root_strategy("rsync://", "rsync://");
}
END_TEST

Suite *rsync_load_suite(void)
{
	Suite *suite;
	TCase *core, *prefix_equals, *uri_list, *test_get_prefix;

	core = tcase_create("Core");
	tcase_add_test(core, rsync_load_normal);

	prefix_equals = tcase_create("PrefixEquals");
	tcase_add_test(prefix_equals, rsync_test_prefix_equals);

	uri_list = tcase_create("uriList");
	tcase_add_test(uri_list, rsync_test_list);

	test_get_prefix = tcase_create("test_get_prefix");
	tcase_add_test(test_get_prefix, rsync_test_get_prefix);

	suite = suite_create("rsync_test()");
	suite_add_tcase(suite, core);
	suite_add_tcase(suite, prefix_equals);
	suite_add_tcase(suite, uri_list);
	suite_add_tcase(suite, test_get_prefix);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = rsync_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
