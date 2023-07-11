#include <check.h>
#include <stdlib.h>

#define INITIAL_CAPACITY 8

#include "alloc.c"
#include "mock.c"
#include "data_structure/path_builder.c"

/* Mocks */

__MOCK_ABORT(uri_get_global, char const *, NULL, struct rpki_uri *uri)
__MOCK_ABORT(uri_get_global_len, size_t, 0, struct rpki_uri *uri)

/* Tests */

#define CHECK_PB(_len, _capacity, _error)				\
	ck_assert_uint_eq(_len, pb.len);				\
	ck_assert_uint_eq(_capacity, pb.capacity);			\
	ck_assert_int_eq(_error, pb.error)

#define CHECK_RESULTS(expected)						\
	ck_assert_uint_eq(0, path_peek(&pb, &peek_result));		\
	ck_assert_str_eq(expected, peek_result);			\
	ck_assert_uint_eq(0, path_compile(&pb, &compile_result));	\
	ck_assert_str_eq(expected, compile_result);			\
	free(compile_result);

#define CHECK_ERROR							\
	ck_assert_uint_eq(EINVAL, path_peek(&pb, &peek_result));	\
	ck_assert_uint_eq(EINVAL, path_compile(&pb, &compile_result));

START_TEST(test_append)
{
	struct path_builder pb;
	char const *peek_result;
	char *compile_result;

	path_init(&pb);
	path_append(&pb, "");
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	path_init(&pb);
	path_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	CHECK_RESULTS("a");

	path_init(&pb);
	path_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	path_init(&pb);
	path_append(&pb, "a/b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	path_init(&pb);
	path_append(&pb, "a/");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "b/");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	/* notes from .h */
	path_init(&pb);
	path_append(&pb, "a/");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	path_init(&pb);
	path_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "/b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	path_init(&pb);
	path_append(&pb, "a/");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "/b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	path_init(&pb);
	path_append(&pb, "//a");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "///");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "b////");
	CHECK_PB(3, 8, 0);
	path_append(&pb, "/////c//////");
	CHECK_PB(5, 8, 0);
	CHECK_RESULTS("a/b/c");

	path_init(&pb);
	path_append(&pb, "//a///b//c//");
	CHECK_PB(5, 8, 0);
	CHECK_RESULTS("a/b/c");
}
END_TEST

/* Actually mainly designed to manhandle capacity expansion */
START_TEST(test_uint)
{
	struct path_builder pb;
	char const *peek_result;
	char *compile_result;

	path_init(&pb);
	path_append_uint(&pb, 291);
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("123"); /* hex */

	path_init(&pb);
	path_append_uint(&pb, 19088743);
	CHECK_PB(7, 8, 0);
	CHECK_RESULTS("1234567");

	path_init(&pb);
	path_append_uint(&pb, 305419896);
	CHECK_PB(8, 16, 0);
	CHECK_RESULTS("12345678");

	path_init(&pb);
	path_append_uint(&pb, 74565);
	CHECK_PB(5, 8, 0);
	path_append_uint(&pb, 7);
	CHECK_PB(7, 8, 0);
	CHECK_RESULTS("12345/7");

	path_init(&pb);
	path_append_uint(&pb, 74565);
	CHECK_PB(5, 8, 0);
	path_append_uint(&pb, 120);
	CHECK_PB(8, 16, 0);
	CHECK_RESULTS("12345/78");

	path_init(&pb);
	path_append_uint(&pb, 74565);
	CHECK_PB(5, 8, 0);
	path_append_uint(&pb, 1929);
	CHECK_PB(9, 16, 0);
	CHECK_RESULTS("12345/789");
}
END_TEST

START_TEST(test_pop)
{
	struct path_builder pb;
	char const *peek_result;
	char *compile_result;

	path_init(&pb);
	path_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	path_pop(&pb, false);
	CHECK_PB(1, 8, 0);
	CHECK_RESULTS("a");

	path_init(&pb);
	path_append(&pb, "abc");
	CHECK_PB(3, 8, 0);
	path_append(&pb, "def");
	CHECK_PB(7, 8, 0);
	path_pop(&pb, false);
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("abc");

	path_init(&pb);
	path_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	path_pop(&pb, false);
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	path_init(&pb);
	path_append(&pb, "/a");
	CHECK_PB(1, 8, 0);
	path_pop(&pb, false);
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	path_init(&pb);
	path_pop(&pb, false);
	CHECK_PB(0, 8, EINVAL);
	CHECK_ERROR;

	path_init(&pb);
	path_append(&pb, "a");
	path_pop(&pb, false);
	CHECK_PB(0, 8, 0);
	path_pop(&pb, false);
	CHECK_PB(0, 8, EINVAL);
	CHECK_ERROR;

//	path_init(&pb);
//	path_append(&pb, "/");
//	CHECK_PB(1, 8, 0);
//	path_pop(&pb);
//	CHECK_PB(0, 8, 0);
//	CHECK_RESULTS("");
//
//	path_init(&pb);
//	path_append(&pb, "///");
//	CHECK_PB(3, 8, 0);
//	path_pop(&pb);
//	CHECK_PB(2, 8, 0);
//	path_pop(&pb);
//	CHECK_PB(1, 8, 0);
//	path_pop(&pb);
//	CHECK_PB(0, 8, 0);
//	CHECK_RESULTS("");
}
END_TEST

START_TEST(test_peek)
{
	struct path_builder pb;
	char const *peek_result;

	/*
	 * Most of path_peek() has already been tested above,
	 * just check it leaves the pb in a stable state.
	 */

	path_init(&pb);

	path_peek(&pb, &peek_result);
	ck_assert_str_eq("", peek_result);

	path_append(&pb, "a");
	path_peek(&pb, &peek_result);
	ck_assert_str_eq("a", peek_result);

	path_append(&pb, "b");
	path_peek(&pb, &peek_result);
	ck_assert_str_eq("a/b", peek_result);

	path_pop(&pb, true);
	path_peek(&pb, &peek_result);
	ck_assert_str_eq("a", peek_result);

	path_pop(&pb, true);
	path_peek(&pb, &peek_result);
	ck_assert_str_eq("", peek_result);

	free(pb.string);
}
END_TEST

START_TEST(test_reverse)
{
	struct path_builder pb;
	char const *peek_result;
	char *compile_result;

	/* 0 components */
	path_init(&pb);
	path_reverse(&pb);
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	/* 1 component */
	path_init(&pb);
	path_append(&pb, "a");
	path_reverse(&pb);
	CHECK_PB(1, 8, 0);
	CHECK_RESULTS("a");

	/* 2 components */
	path_init(&pb);
	path_append(&pb, "a");
	path_append(&pb, "b");
	path_reverse(&pb);
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("b/a");

	path_init(&pb);
	path_append(&pb, "abc");
	path_append(&pb, "def");
	path_reverse(&pb);
	CHECK_PB(7, 8, 0);
	CHECK_RESULTS("def/abc");

	path_init(&pb);
	path_append(&pb, "abcd");
	path_append(&pb, "efgh");
	path_reverse(&pb);
	CHECK_PB(9, 16, 0);
	CHECK_RESULTS("efgh/abcd");

	path_init(&pb);
	path_append(&pb, "abc");
	path_append(&pb, "efgh");
	path_reverse(&pb);
	CHECK_PB(8, 8, 0);
	CHECK_RESULTS("efgh/abc");

	path_init(&pb);
	path_append(&pb, "abcd");
	path_append(&pb, "fgh");
	path_reverse(&pb);
	CHECK_PB(8, 8, 0);
	CHECK_RESULTS("fgh/abcd");

	/* 3 components */
	path_init(&pb);
	path_append(&pb, "abc");
	path_append(&pb, "def");
	path_append(&pb, "ghi");
	path_reverse(&pb);
	CHECK_PB(11, 16, 0);
	CHECK_RESULTS("ghi/def/abc");

	path_init(&pb);
	path_append(&pb, "ab");
	path_append(&pb, "cde");
	path_append(&pb, "fghi");
	path_reverse(&pb);
	CHECK_PB(11, 16, 0);
	CHECK_RESULTS("fghi/cde/ab");

	/* 4 components */
	path_init(&pb);
	path_append(&pb, "a");
	path_append(&pb, "b");
	path_append(&pb, "c");
	path_append(&pb, "d");
	path_reverse(&pb);
	CHECK_PB(7, 8, 0);
	CHECK_RESULTS("d/c/b/a");

	path_init(&pb);
	path_append(&pb, "ab");
	path_append(&pb, "cd");
	path_append(&pb, "ef");
	path_append(&pb, "gh");
	path_reverse(&pb);
	CHECK_PB(11, 16, 0);
	CHECK_RESULTS("gh/ef/cd/ab");

	path_init(&pb);
	path_append(&pb, "a");
	path_append(&pb, "bcd");
	path_append(&pb, "efgh");
	path_append(&pb, "ijklm");
	path_reverse(&pb);
	CHECK_PB(16, 16, 0);
	CHECK_RESULTS("ijklm/efgh/bcd/a");

	path_init(&pb);
	path_append(&pb, "abcdefghijklmnopq");
	path_append(&pb, "r");
	path_append(&pb, "stu");
	path_append(&pb, "vx");
	path_reverse(&pb);
	CHECK_PB(26, 32, 0);
	CHECK_RESULTS("vx/stu/r/abcdefghijklmnopq");
}
END_TEST

START_TEST(test_normalization)
{
	struct path_builder pb;
	char const *peek_result;
	char *compile_result;

	path_init(&pb);
	path_append(&pb, ".");
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	path_init(&pb);
	path_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	path_append(&pb, ".");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	path_init(&pb);
	path_append(&pb, ".");
	CHECK_PB(0, 8, 0);
	path_append(&pb, ".");
	CHECK_PB(0, 8, 0);
	path_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	path_append(&pb, ".");
	CHECK_PB(1, 8, 0);
	path_append(&pb, ".");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	path_append(&pb, ".");
	CHECK_PB(3, 8, 0);
	path_append(&pb, ".");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	path_init(&pb);
	path_append(&pb, "..");
	CHECK_PB(0, 8, EINVAL);
	CHECK_ERROR;

	path_init(&pb);
	path_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	path_append(&pb, "..");
	CHECK_PB(1, 8, 0);
	CHECK_RESULTS("a");

	path_init(&pb);
	path_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	path_append(&pb, "..");
	CHECK_PB(1, 8, 0);
	path_append(&pb, ".");
	CHECK_PB(1, 8, 0);
	path_append(&pb, "..");
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	/* dot dot injection */
	path_init(&pb);
	path_append(&pb, "a/../b");
	CHECK_PB(1, 8, 0);
	CHECK_RESULTS("b");
}
END_TEST

Suite *
pdu_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("functions");
	tcase_add_test(core, test_append);
	tcase_add_test(core, test_uint);
	tcase_add_test(core, test_pop);
	tcase_add_test(core, test_peek);
	tcase_add_test(core, test_reverse);
	tcase_add_test(core, test_normalization);

	suite = suite_create("path_builder");
	suite_add_tcase(suite, core);
	return suite;
}

int
main(int argc, char **argv)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = pdu_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
