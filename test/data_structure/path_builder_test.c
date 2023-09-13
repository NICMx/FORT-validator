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
	ck_assert_uint_eq(0, pb_peek(&pb, &peek_result));		\
	ck_assert_str_eq(expected, peek_result);			\
	ck_assert_uint_eq(0, pb_compile(&pb, &compile_result));	\
	ck_assert_str_eq(expected, compile_result);			\
	free(compile_result);

#define CHECK_ERROR							\
	ck_assert_uint_eq(EINVAL, pb_peek(&pb, &peek_result));	\
	ck_assert_uint_eq(EINVAL, pb_compile(&pb, &compile_result));

START_TEST(test_append)
{
	struct path_builder pb;
	char const *peek_result;
	char *compile_result;

	pb_init(&pb);
	pb_append(&pb, "");
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	pb_init(&pb);
	pb_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	CHECK_RESULTS("a");

	pb_init(&pb);
	pb_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	pb_init(&pb);
	pb_append(&pb, "a/b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	pb_init(&pb);
	pb_append(&pb, "a/");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "b/");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	/* notes from .h */
	pb_init(&pb);
	pb_append(&pb, "a/");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	pb_init(&pb);
	pb_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "/b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	pb_init(&pb);
	pb_append(&pb, "a/");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "/b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	pb_init(&pb);
	pb_append(&pb, "//a");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "///");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "b////");
	CHECK_PB(3, 8, 0);
	pb_append(&pb, "/////c//////");
	CHECK_PB(5, 8, 0);
	CHECK_RESULTS("a/b/c");

	pb_init(&pb);
	pb_append(&pb, "//a///b//c//");
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

	pb_init(&pb);
	pb_append_uint(&pb, 291);
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("123"); /* hex */

	pb_init(&pb);
	pb_append_uint(&pb, 19088743);
	CHECK_PB(7, 8, 0);
	CHECK_RESULTS("1234567");

	pb_init(&pb);
	pb_append_uint(&pb, 305419896);
	CHECK_PB(8, 16, 0);
	CHECK_RESULTS("12345678");

	pb_init(&pb);
	pb_append_uint(&pb, 74565);
	CHECK_PB(5, 8, 0);
	pb_append_uint(&pb, 7);
	CHECK_PB(7, 8, 0);
	CHECK_RESULTS("12345/7");

	pb_init(&pb);
	pb_append_uint(&pb, 74565);
	CHECK_PB(5, 8, 0);
	pb_append_uint(&pb, 120);
	CHECK_PB(8, 16, 0);
	CHECK_RESULTS("12345/78");

	pb_init(&pb);
	pb_append_uint(&pb, 74565);
	CHECK_PB(5, 8, 0);
	pb_append_uint(&pb, 1929);
	CHECK_PB(9, 16, 0);
	CHECK_RESULTS("12345/789");
}
END_TEST

START_TEST(test_pop)
{
	struct path_builder pb;
	char const *peek_result;
	char *compile_result;

	pb_init(&pb);
	pb_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	pb_pop(&pb, false);
	CHECK_PB(1, 8, 0);
	CHECK_RESULTS("a");

	pb_init(&pb);
	pb_append(&pb, "abc");
	CHECK_PB(3, 8, 0);
	pb_append(&pb, "def");
	CHECK_PB(7, 8, 0);
	pb_pop(&pb, false);
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("abc");

	pb_init(&pb);
	pb_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	pb_pop(&pb, false);
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	pb_init(&pb);
	pb_append(&pb, "/a");
	CHECK_PB(1, 8, 0);
	pb_pop(&pb, false);
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	pb_init(&pb);
	pb_pop(&pb, false);
	CHECK_PB(0, 8, EINVAL);
	CHECK_ERROR;

	pb_init(&pb);
	pb_append(&pb, "a");
	pb_pop(&pb, false);
	CHECK_PB(0, 8, 0);
	pb_pop(&pb, false);
	CHECK_PB(0, 8, EINVAL);
	CHECK_ERROR;

//	pb_init(&pb);
//	pb_append(&pb, "/");
//	CHECK_PB(1, 8, 0);
//	pb_pop(&pb);
//	CHECK_PB(0, 8, 0);
//	CHECK_RESULTS("");
//
//	pb_init(&pb);
//	pb_append(&pb, "///");
//	CHECK_PB(3, 8, 0);
//	pb_pop(&pb);
//	CHECK_PB(2, 8, 0);
//	pb_pop(&pb);
//	CHECK_PB(1, 8, 0);
//	pb_pop(&pb);
//	CHECK_PB(0, 8, 0);
//	CHECK_RESULTS("");
}
END_TEST

START_TEST(test_peek)
{
	struct path_builder pb;
	char const *peek_result;

	/*
	 * Most of pb_peek() has already been tested above,
	 * just check it leaves the pb in a stable state.
	 */

	pb_init(&pb);

	pb_peek(&pb, &peek_result);
	ck_assert_str_eq("", peek_result);

	pb_append(&pb, "a");
	pb_peek(&pb, &peek_result);
	ck_assert_str_eq("a", peek_result);

	pb_append(&pb, "b");
	pb_peek(&pb, &peek_result);
	ck_assert_str_eq("a/b", peek_result);

	pb_pop(&pb, true);
	pb_peek(&pb, &peek_result);
	ck_assert_str_eq("a", peek_result);

	pb_pop(&pb, true);
	pb_peek(&pb, &peek_result);
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
	pb_init(&pb);
	pb_reverse(&pb);
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	/* 1 component */
	pb_init(&pb);
	pb_append(&pb, "a");
	pb_reverse(&pb);
	CHECK_PB(1, 8, 0);
	CHECK_RESULTS("a");

	/* 2 components */
	pb_init(&pb);
	pb_append(&pb, "a");
	pb_append(&pb, "b");
	pb_reverse(&pb);
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("b/a");

	pb_init(&pb);
	pb_append(&pb, "abc");
	pb_append(&pb, "def");
	pb_reverse(&pb);
	CHECK_PB(7, 8, 0);
	CHECK_RESULTS("def/abc");

	pb_init(&pb);
	pb_append(&pb, "abcd");
	pb_append(&pb, "efgh");
	pb_reverse(&pb);
	CHECK_PB(9, 16, 0);
	CHECK_RESULTS("efgh/abcd");

	pb_init(&pb);
	pb_append(&pb, "abc");
	pb_append(&pb, "efgh");
	pb_reverse(&pb);
	CHECK_PB(8, 8, 0);
	CHECK_RESULTS("efgh/abc");

	pb_init(&pb);
	pb_append(&pb, "abcd");
	pb_append(&pb, "fgh");
	pb_reverse(&pb);
	CHECK_PB(8, 8, 0);
	CHECK_RESULTS("fgh/abcd");

	/* 3 components */
	pb_init(&pb);
	pb_append(&pb, "abc");
	pb_append(&pb, "def");
	pb_append(&pb, "ghi");
	pb_reverse(&pb);
	CHECK_PB(11, 16, 0);
	CHECK_RESULTS("ghi/def/abc");

	pb_init(&pb);
	pb_append(&pb, "ab");
	pb_append(&pb, "cde");
	pb_append(&pb, "fghi");
	pb_reverse(&pb);
	CHECK_PB(11, 16, 0);
	CHECK_RESULTS("fghi/cde/ab");

	/* 4 components */
	pb_init(&pb);
	pb_append(&pb, "a");
	pb_append(&pb, "b");
	pb_append(&pb, "c");
	pb_append(&pb, "d");
	pb_reverse(&pb);
	CHECK_PB(7, 8, 0);
	CHECK_RESULTS("d/c/b/a");

	pb_init(&pb);
	pb_append(&pb, "ab");
	pb_append(&pb, "cd");
	pb_append(&pb, "ef");
	pb_append(&pb, "gh");
	pb_reverse(&pb);
	CHECK_PB(11, 16, 0);
	CHECK_RESULTS("gh/ef/cd/ab");

	pb_init(&pb);
	pb_append(&pb, "a");
	pb_append(&pb, "bcd");
	pb_append(&pb, "efgh");
	pb_append(&pb, "ijklm");
	pb_reverse(&pb);
	CHECK_PB(16, 16, 0);
	CHECK_RESULTS("ijklm/efgh/bcd/a");

	pb_init(&pb);
	pb_append(&pb, "abcdefghijklmnopq");
	pb_append(&pb, "r");
	pb_append(&pb, "stu");
	pb_append(&pb, "vx");
	pb_reverse(&pb);
	CHECK_PB(26, 32, 0);
	CHECK_RESULTS("vx/stu/r/abcdefghijklmnopq");
}
END_TEST

START_TEST(test_normalization)
{
	struct path_builder pb;
	char const *peek_result;
	char *compile_result;

	pb_init(&pb);
	pb_append(&pb, ".");
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	pb_init(&pb);
	pb_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, ".");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	pb_init(&pb);
	pb_append(&pb, ".");
	CHECK_PB(0, 8, 0);
	pb_append(&pb, ".");
	CHECK_PB(0, 8, 0);
	pb_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, ".");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, ".");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	pb_append(&pb, ".");
	CHECK_PB(3, 8, 0);
	pb_append(&pb, ".");
	CHECK_PB(3, 8, 0);
	CHECK_RESULTS("a/b");

	pb_init(&pb);
	pb_append(&pb, "..");
	CHECK_PB(0, 8, EINVAL);
	CHECK_ERROR;

	pb_init(&pb);
	pb_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	pb_append(&pb, "..");
	CHECK_PB(1, 8, 0);
	CHECK_RESULTS("a");

	pb_init(&pb);
	pb_append(&pb, "a");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "b");
	CHECK_PB(3, 8, 0);
	pb_append(&pb, "..");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, ".");
	CHECK_PB(1, 8, 0);
	pb_append(&pb, "..");
	CHECK_PB(0, 8, 0);
	CHECK_RESULTS("");

	/* dot dot injection */
	pb_init(&pb);
	pb_append(&pb, "a/../b");
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
