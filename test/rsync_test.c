#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "str_token.c"
#include "types/uri.c"
#include "rsync/rsync.c"

/* Mocks */

MOCK_NULL(state_retrieve, struct validation *, void)
MOCK_ABORT_PTR(validation_rsync_visited_uris, uri_list, struct validation *s)

/* Tests */

static void
__mark_as_downloaded(char *uri_str, struct uri_list *visited_uris)
{
	struct rpki_uri *uri;
	ck_assert_int_eq(0, uri_create_rsync_str(&uri, uri_str, strlen(uri_str)));
	mark_as_downloaded(uri, visited_uris);
	uri_refput(uri);
}

static void
assert_downloaded(char *uri_str, struct uri_list *visited_uris, bool expected)
{
	struct rpki_uri *uri;
	ck_assert_int_eq(0, uri_create_rsync_str(&uri, uri_str, strlen(uri_str)));
	ck_assert_int_eq(is_already_downloaded(uri, visited_uris), expected);
	uri_refput(uri);
}

START_TEST(rsync_test_list)
{
	struct uri_list *visited_uris;

	visited_uris = rsync_create();
	ck_assert_ptr_nonnull(visited_uris);

	__mark_as_downloaded("rsync://example.foo/repository/", visited_uris);
	__mark_as_downloaded("rsync://example.foo/member_repository/",
	    visited_uris);
	__mark_as_downloaded("rsync://example.foz/repository/", visited_uris);
	__mark_as_downloaded("rsync://example.boo/repo/", visited_uris);
	__mark_as_downloaded("rsync://example.potato/rpki/", visited_uris);

	assert_downloaded("rsync://example.foo/repository/", visited_uris,
	    true);
	assert_downloaded("rsync://example.foo/repository/abc/cdfg",
	    visited_uris, false);
	assert_downloaded("rsync://example.foo/member_repository/bca",
	    visited_uris, false);
	assert_downloaded("rsync://example.boo/repository/", visited_uris,
	    false);
	assert_downloaded("rsync://example.potato/repository/", visited_uris,
	    false);
	assert_downloaded("rsync://example.potato/rpki/abc/", visited_uris,
	    false);

	rsync_destroy(visited_uris);
}
END_TEST

Suite *rsync_load_suite(void)
{
	Suite *suite;
	TCase *uri_list;

	uri_list = tcase_create("uriList");
	tcase_add_test(uri_list, rsync_test_list);

	suite = suite_create("rsync_test()");
	suite_add_tcase(suite, uri_list);

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
