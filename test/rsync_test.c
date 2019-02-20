#include "rsync/rsync.c"

#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "common.h"

START_TEST(rsync_load_normal)
{

}
END_TEST

START_TEST(rsync_test_prefix_equals)
{
	struct uri rsync_uri;
	char *uri = "proto://a/b/c";

	rsync_uri.len = strlen(uri);
	rsync_uri.string = uri;

	ck_assert_int_eq(rsync_uri_prefix_equals(&rsync_uri, "proto://a/b/c"), true);
	ck_assert_int_eq(rsync_uri_prefix_equals(&rsync_uri, "proto://a/b/"), false);
	ck_assert_int_eq(rsync_uri_prefix_equals(&rsync_uri, "proto://a/b/c/c"), true);
	ck_assert_int_eq(rsync_uri_prefix_equals(&rsync_uri, "proto://a/b/cc"), false);
	ck_assert_int_eq(rsync_uri_prefix_equals(&rsync_uri, "proto://a/b/cc/"), false);

	uri = "proto://a/b/c/";
	rsync_uri.len = strlen(uri);
	rsync_uri.string = uri;
	ck_assert_int_eq(rsync_uri_prefix_equals(&rsync_uri, "proto://a/b/c"), false);
	ck_assert_int_eq(rsync_uri_prefix_equals(&rsync_uri, "proto://a/b/"), false);
	ck_assert_int_eq(rsync_uri_prefix_equals(&rsync_uri, "proto://a/b/c/c"), true);
	ck_assert_int_eq(rsync_uri_prefix_equals(&rsync_uri, "proto://a/b/cc"), false);
	ck_assert_int_eq(rsync_uri_prefix_equals(&rsync_uri, "proto://a/b/cc/"), false);

}
END_TEST

START_TEST(rsync_test_list)
{
	struct uri *uri;
	char *string_uri, *test_string;

	rsync_init(true);

	string_uri = "rsync://example.foo/repository/";
	ck_assert_int_eq(add_uri_to_list(string_uri), 0);
	string_uri = "rsync://example.foo/member_repository/";
	ck_assert_int_eq(add_uri_to_list(string_uri), 0);
	string_uri = "rsync://example.foz/repository/";
	ck_assert_int_eq(add_uri_to_list(string_uri), 0);
	string_uri = "rsync://example.boo/repo/";
	ck_assert_int_eq(add_uri_to_list(string_uri), 0);
	string_uri = "rsync://example.potato/rpki/";
	ck_assert_int_eq(add_uri_to_list(string_uri), 0);

	test_string = "rsync://example.foo/repository/";
	ck_assert_int_eq(is_uri_in_list(test_string), true);
	test_string = "rsync://example.foo/repository/abc/cdfg";
	ck_assert_int_eq(is_uri_in_list(test_string), true);
	test_string = "rsync://example.foo/member_repository/bca";
	ck_assert_int_eq(is_uri_in_list(test_string), true);
	test_string = "rsync://example.boo/repository/";
	ck_assert_int_eq(is_uri_in_list(test_string), false);
	test_string = "rsync://example.potato/repository/";
	ck_assert_int_eq(is_uri_in_list(test_string), false);
	test_string = "rsync://example.potato/rpki/abc/";
	ck_assert_int_eq(is_uri_in_list(test_string), true);

	/* rsync destroy */
	while(!SLIST_EMPTY(rsync_uris)) {
		uri = SLIST_FIRST(rsync_uris);
		SLIST_REMOVE_HEAD(rsync_uris, next);
		free(uri);
	}

	free(rsync_uris);
}
END_TEST

static int
malloc_string(char *string, char **result)
{
	*result = malloc(strlen(string) + 1);
	if (*result == NULL) {
		return pr_enomem();
	}

	strcpy(*result, string);
	return 0;
}

static void
test_get_path(char *test, char *expected)
{
	int error;
	char *string, *result;
	size_t rsync_prefix_len = strlen("rsync://");

	error = malloc_string(test, &string);
	if (error)
		return;

	error = get_path_only(string, strlen(string), rsync_prefix_len, &result);
	if (error) {
		free(string);
		return;
	}

	ck_assert_str_eq(expected, result);
	ck_assert_str_eq(string, test);
	free(string);
	free(result);

	return;
}

START_TEST(rsync_test_get_path)
{
	test_get_path("rsync://www.example.com/", "rsync://www.example.com/");
	test_get_path("rsync://www.example.com", "rsync://www.example.com/");
	test_get_path("rsync://www.example.com/test", "rsync://www.example.com/");
	test_get_path("rsync://www.example.com/test/", "rsync://www.example.com/test/");
	test_get_path("rsync://www.example.com/test/abc", "rsync://www.example.com/test/");
	test_get_path("rsync://www.example.com/test/abc/", "rsync://www.example.com/test/abc/");
	test_get_path("rsync://www.example.com/test/abc/abc.file", "rsync://www.example.com/test/abc/");
	test_get_path("rsync://www.example.com/test/file.txt", "rsync://www.example.com/test/");
}
END_TEST

static void
test_get_prefix_from_URIs(char *expected, char *stored_uri, char *new_uri)
{
	int error;
	char *result;
	error = find_prefix_path(new_uri, stored_uri, &result);

	if (error)
		return;

	if (expected == NULL) {
		ck_assert_ptr_eq(expected, result);
	} else {
		ck_assert_str_eq(expected, result);
	}

	if (result != NULL)
		free(result);
}

START_TEST(rsync_test_get_prefix)
{
	char *expected, *stored_uri, *new_uri;

	new_uri = "rsync://www.example1.com/test/foo/";
	stored_uri = "rsync://www.example1.com/test/bar/";
	expected = "rsync://www.example1.com/test/";
	test_get_prefix_from_URIs(expected, stored_uri, new_uri);

	new_uri = "rsync://www.example2.com/test/foo/";
	stored_uri = "rsync://www.example2.co/test/bar/";
	expected = NULL;
	test_get_prefix_from_URIs(expected, stored_uri, new_uri);

	new_uri = "rsync://www.example3.com/test/foo/";
	stored_uri = "rsync://www.example3.com/test/foo/test/";
	expected = "rsync://www.example3.com/test/foo/";
	test_get_prefix_from_URIs(expected, stored_uri, new_uri);

	new_uri = "rsync://www.example4.com/test/";
	stored_uri = "rsync://www.example4.com/test/foo/bar";
	expected = "rsync://www.example4.com/test/";
	test_get_prefix_from_URIs(expected, stored_uri, new_uri);

	new_uri = "rsync://www.example5.com/foo/";
	stored_uri = "rsync://www.example5.com/bar/";
	expected = NULL;
	test_get_prefix_from_URIs(expected, stored_uri, new_uri);

	new_uri = "rsync://www.example6.com/bar/foo/";
	stored_uri = "rsync://www.example6.com/bar/";
	expected = "rsync://www.example6.com/bar/";
	test_get_prefix_from_URIs(expected, stored_uri, new_uri);

	new_uri = "rsync://www.example7.com/";
	stored_uri = "rsync://www.example7.com/bar/";
	expected = NULL;
	test_get_prefix_from_URIs(expected, stored_uri, new_uri);

	new_uri = "rsync://www.example8.com/bar";
	stored_uri = "rsync://www.example8.com/";
	expected = NULL;
	test_get_prefix_from_URIs(expected, stored_uri, new_uri);

	new_uri = "rsync://www.example9.com/bar/";
	stored_uri = "rsync://www.example9.com/bar/";
	expected = "rsync://www.example9.com/bar/";
	test_get_prefix_from_URIs(expected, stored_uri, new_uri);

}
END_TEST

Suite *rsync_load_suite(void)
{
	Suite *suite;
	TCase *core, *prefix_equals, *uri_list, *test_get_path, *test_get_prefix;

	core = tcase_create("Core");
	tcase_add_test(core, rsync_load_normal);

	prefix_equals = tcase_create("PrefixEquals");
	tcase_add_test(prefix_equals, rsync_test_prefix_equals);

	uri_list = tcase_create("uriList");
	tcase_add_test(uri_list, rsync_test_list);

	test_get_path = tcase_create("test_static_get_path");
	tcase_add_test(test_get_path, rsync_test_get_path);

	test_get_prefix = tcase_create("test_get_prefix");
	tcase_add_test(test_get_prefix, rsync_test_get_prefix);

	suite = suite_create("rsync_test()");
	suite_add_tcase(suite, core);
	suite_add_tcase(suite, prefix_equals);
	suite_add_tcase(suite, uri_list);
	suite_add_tcase(suite, test_get_path);
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
