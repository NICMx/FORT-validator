#include <check.h>
#include <stdlib.h>

#define INITIAL_CAPACITY 8

#include "alloc.c"
#include "mock.c"
#include "data_structure/path_builder.c"

#define CHECK_PB(_string, _capacity)					\
	ck_assert_str_eq(_string, pb.string);				\
	ck_assert_uint_eq(strlen(_string), pb.len);			\
	ck_assert_uint_eq(_capacity, pb.capacity);

START_TEST(test_append)
{
	struct path_builder pb;

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, ""));
	CHECK_PB("", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a"));
	CHECK_PB("a", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "/a"));
	CHECK_PB("/a", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a"));
	CHECK_PB("a", 8);
	ck_assert_int_eq(0, pb_append(&pb, "b"));
	CHECK_PB("a/b", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a/b"));
	CHECK_PB("a/b", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a/"));
	CHECK_PB("a/", 8);
	ck_assert_int_eq(0, pb_append(&pb, "b/"));
	CHECK_PB("a//b/", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a/"));
	CHECK_PB("a/", 8);
	ck_assert_int_eq(0, pb_append(&pb, "b"));
	CHECK_PB("a//b", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a"));
	CHECK_PB("a", 8);
	ck_assert_int_eq(0, pb_append(&pb, "/b"));
	CHECK_PB("a//b", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a/"));
	CHECK_PB("a/", 8);
	ck_assert_int_eq(0, pb_append(&pb, "/b"));
	CHECK_PB("a///b", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "//a"));
	CHECK_PB("//a", 8);
	ck_assert_int_eq(0, pb_append(&pb, "///"));
	CHECK_PB("//a////", 8);
	ck_assert_int_eq(0, pb_append(&pb, "b////"));
	CHECK_PB("//a/////b////", 16);
	ck_assert_int_eq(0, pb_append(&pb, "/////c//////"));
	CHECK_PB("//a/////b//////////c//////", 32);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "//a///b//c//"));
	CHECK_PB("//a///b//c//", 16);
	pb_cleanup(&pb);
}
END_TEST

/* Actually mainly designed to manhandle capacity expansion */
START_TEST(test_uint)
{
	struct path_builder pb;

	pb_init(&pb);
	pb_append_u32(&pb, 0x123);
	CHECK_PB("123", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	pb_append_u32(&pb, 0x1234567);
	CHECK_PB("1234567", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	pb_append_u32(&pb, 0x12345678);
	CHECK_PB("12345678", 16);
	pb_cleanup(&pb);

	pb_init(&pb);
	pb_append_u32(&pb, 0x12345);
	CHECK_PB("12345", 8);
	pb_append_u32(&pb, 0x7);
	CHECK_PB("12345/7", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	pb_append_u32(&pb, 0x12345);
	CHECK_PB("12345", 8);
	pb_append_u32(&pb, 0x78);
	CHECK_PB("12345/78", 16);
	pb_cleanup(&pb);

	pb_init(&pb);
	pb_append_u32(&pb, 0x12345);
	CHECK_PB("12345", 8);
	pb_append_u32(&pb, 0x789);
	CHECK_PB("12345/789", 16);
	pb_cleanup(&pb);
}
END_TEST

START_TEST(test_pop)
{
	struct path_builder pb;

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a"));
	CHECK_PB("a", 8);
	ck_assert_int_eq(0, pb_append(&pb, "b"));
	CHECK_PB("a/b", 8);
	ck_assert_int_eq(0, pb_pop(&pb, false));
	CHECK_PB("a", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "abc"));
	CHECK_PB("abc", 8);
	ck_assert_int_eq(0, pb_append(&pb, "def"));
	CHECK_PB("abc/def", 8);
	ck_assert_int_eq(0, pb_pop(&pb, false));
	CHECK_PB("abc", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a"));
	CHECK_PB("a", 8);
	ck_assert_int_eq(0, pb_pop(&pb, false));
	CHECK_PB("", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "/a"));
	CHECK_PB("/a", 8);
	ck_assert_int_eq(0, pb_pop(&pb, false));
	CHECK_PB("/", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(EINVAL, pb_pop(&pb, false));
	CHECK_PB("", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a"));
	ck_assert_int_eq(0, pb_pop(&pb, false));
	CHECK_PB("", 8);
	ck_assert_int_eq(EINVAL, pb_pop(&pb, false));
	CHECK_PB("", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "/"));
	CHECK_PB("/", 8);
	ck_assert_int_eq(EINVAL, pb_pop(&pb, false));
	CHECK_PB("/", 8);
	pb_cleanup(&pb);
}
END_TEST

START_TEST(test_reverse)
{
	struct path_builder pb;

	/* 0 components */
	pb_init(&pb);
	pb_reverse(&pb);
	CHECK_PB("", 8);
	pb_cleanup(&pb);

	/* 1 component */
	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a"));
	pb_reverse(&pb);
	CHECK_PB("a", 8);
	pb_cleanup(&pb);

	/* 2 components */
	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a"));
	ck_assert_int_eq(0, pb_append(&pb, "b"));
	pb_reverse(&pb);
	CHECK_PB("b/a", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "abc"));
	ck_assert_int_eq(0, pb_append(&pb, "def"));
	pb_reverse(&pb);
	CHECK_PB("def/abc", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "abcd"));
	ck_assert_int_eq(0, pb_append(&pb, "efgh"));
	pb_reverse(&pb);
	CHECK_PB("efgh/abcd", 16);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "abc"));
	ck_assert_int_eq(0, pb_append(&pb, "efgh"));
	pb_reverse(&pb);
	CHECK_PB("efgh/abc", 16);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "abcd"));
	ck_assert_int_eq(0, pb_append(&pb, "fgh"));
	pb_reverse(&pb);
	CHECK_PB("fgh/abcd", 16);
	pb_cleanup(&pb);

	/* 3 components */
	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "abc"));
	ck_assert_int_eq(0, pb_append(&pb, "def"));
	ck_assert_int_eq(0, pb_append(&pb, "ghi"));
	pb_reverse(&pb);
	CHECK_PB("ghi/def/abc", 16);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "ab"));
	ck_assert_int_eq(0, pb_append(&pb, "cde"));
	ck_assert_int_eq(0, pb_append(&pb, "fghi"));
	pb_reverse(&pb);
	CHECK_PB("fghi/cde/ab", 16);
	pb_cleanup(&pb);

	/* 4 components */
	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a"));
	ck_assert_int_eq(0, pb_append(&pb, "b"));
	ck_assert_int_eq(0, pb_append(&pb, "c"));
	ck_assert_int_eq(0, pb_append(&pb, "d"));
	pb_reverse(&pb);
	CHECK_PB("d/c/b/a", 8);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "ab"));
	ck_assert_int_eq(0, pb_append(&pb, "cd"));
	ck_assert_int_eq(0, pb_append(&pb, "ef"));
	ck_assert_int_eq(0, pb_append(&pb, "gh"));
	pb_reverse(&pb);
	CHECK_PB("gh/ef/cd/ab", 16);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "a"));
	ck_assert_int_eq(0, pb_append(&pb, "bcd"));
	ck_assert_int_eq(0, pb_append(&pb, "efgh"));
	ck_assert_int_eq(0, pb_append(&pb, "ijklm"));
	pb_reverse(&pb);
	CHECK_PB("ijklm/efgh/bcd/a", 32);
	pb_cleanup(&pb);

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "abcdefghijklmnopq"));
	ck_assert_int_eq(0, pb_append(&pb, "r"));
	ck_assert_int_eq(0, pb_append(&pb, "stu"));
	ck_assert_int_eq(0, pb_append(&pb, "vx"));
	pb_reverse(&pb);
	CHECK_PB("vx/stu/r/abcdefghijklmnopq", 32);
	pb_cleanup(&pb);
}
END_TEST

static Suite *
pdu_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("functions");
	tcase_add_test(core, test_append);
	tcase_add_test(core, test_uint);
	tcase_add_test(core, test_pop);
	tcase_add_test(core, test_reverse);

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
