#include "file.c"

#include <check.h>

#include "mock.c"

static void
touch_dir(char const *dir)
{
	ck_assert_int_eq(0, file_mkdir(dir, true));
}

static void
touch_file(char const *file)
{
	int fd;
	int error;

	pr_op_debug("touch %s", file);

	fd = open(file, O_WRONLY | O_CREAT, CACHE_FILEMODE);
	if (fd < 0) {
		error = errno;
		if (error == EEXIST)
			return;
		ck_abort_msg("open(%s): %s", file, strerror(error));
	}

	close(fd);
}

static void
create_test_sandbox(void)
{
	touch_dir ("tmp");
	touch_dir ("tmp/file");
	touch_dir ("tmp/file/abc");

	touch_file("tmp/file/abc/a");

	touch_dir ("tmp/file/abc/b");
	touch_file("tmp/file/abc/b/d");
	touch_file("tmp/file/abc/b/e");

	touch_file("tmp/file/abc/c");
}

START_TEST(test_rm)
{
	create_test_sandbox();

	ck_assert_int_eq(0, file_exists("tmp/file/abc"));
	ck_assert_int_eq(0, file_rm_rf("tmp/file/abc"));
	ck_assert_int_eq(ENOENT, file_exists("tmp/file/abc"));
}
END_TEST

static Suite *create_suite(void)
{
	Suite *suite;
	TCase *rm;

	rm = tcase_create("rm");
	tcase_add_test(rm, test_rm);

	suite = suite_create("File");
	suite_add_tcase(suite, rm);
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
