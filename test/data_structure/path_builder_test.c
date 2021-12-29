#include "data_structure/path_builder.c"

#include <check.h>

#include "impersonator.c"
#include "log.c"

static void
validate_pb(struct path_builder *pb, char const *expected)
{
	char *path;
	ck_assert_int_eq(0, path_compile(pb, &path));
	ck_assert_str_eq(expected, path);
	free(path);
}

START_TEST(path_append_test)
{
	struct path_builder pb;

	path_init(&pb);
	validate_pb(&pb, "");

	path_init(&pb);
	path_append(&pb, "");
	path_append(&pb, "");
	validate_pb(&pb, "");

	path_init(&pb);
	path_append(&pb, "a");
	validate_pb(&pb, "a");

	path_init(&pb);
	path_append(&pb, "a");
	path_append(&pb, "b");
	path_append(&pb, "c");
	validate_pb(&pb, "a/b/c");

	path_init(&pb);
	path_append(&pb, "a/b");
	path_append(&pb, "c");
	validate_pb(&pb, "a/b/c");
}
END_TEST

START_TEST(path_append_url_test)
{
	struct path_builder pb;

	path_init(&pb);
	path_append_url(&pb, "http://a/b/c.txt");
	validate_pb(&pb, "http/a/b/c.txt");

	path_init(&pb);
	path_append_url(&pb, "rsync://a/b/c.txt");
	path_append_url(&pb, "http://d/e/f.txt");
	validate_pb(&pb, "rsync/a/b/c.txt/http/d/e/f.txt");

	path_init(&pb);
	path_append_url(&pb, "abcdef");
	validate_pb(&pb, "abcdef");

	path_init(&pb);
	path_append_url(&pb, "abcdef");
	path_append_url(&pb, "rsync://a/b/c.txt");
	path_append_url(&pb, "http://d/e/f.txt");
	validate_pb(&pb, "abcdef/rsync/a/b/c.txt/http/d/e/f.txt");
}
END_TEST

Suite *path_builder_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, path_append_test);
	tcase_add_test(core, path_append_url_test);

	suite = suite_create("lfile_read()");
	suite_add_tcase(suite, core);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = path_builder_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
