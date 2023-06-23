#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "alloc.c"
#include "file.c"
#include "impersonator.c"
#include "line_file.c"
#include "log.c"

START_TEST(file_line_normal)
{
	struct line_file *lfile;
	char *string, *long_string;
	char *SENTENCE;
	size_t SENTENCE_LEN;
	unsigned int i;

	ck_assert_int_eq(lfile_open("line_file/core.txt", &lfile), 0);

	ck_assert_int_eq(lfile_read(lfile, &string), 0);
	ck_assert_str_eq(string, "This is a normal line.");
	free(string);

	ck_assert_int_eq(lfile_read(lfile, &string), 0);
	ck_assert_str_eq(string, "This is also a normal line, but the following one is empty.");
	free(string);

	ck_assert_int_eq(lfile_read(lfile, &string), 0);
	ck_assert_str_eq(string, "");
	free(string);

	ck_assert_int_eq(lfile_read(lfile, &string), 0);
	ck_assert_str_eq(string, "This one ends with \\r\\n.");
	free(string);

	SENTENCE = "This is a very long line. ";
	SENTENCE_LEN = strlen(SENTENCE);
	long_string = malloc(316 * SENTENCE_LEN + 1);
	ck_assert(long_string);
	for (i = 0; i < 316; i++)
		strcpy(long_string + i * SENTENCE_LEN, SENTENCE);
	ck_assert_int_eq(lfile_read(lfile, &string), 0);
	ck_assert_str_eq(string, long_string);
	free(long_string);
	free(string);

	ck_assert_int_eq(lfile_read(lfile, &string), 0);
	ck_assert_str_eq(string, "This line does not end with a newline.");
	free(string);

	ck_assert_int_eq(lfile_read(lfile, &string), 0);
	ck_assert(string == NULL);

	lfile_close(lfile);
}
END_TEST

START_TEST(file_line_empty)
{
	struct line_file *lfile;
	char *string;

	ck_assert_int_eq(lfile_open("line_file/empty.txt", &lfile), 0);

	ck_assert_int_eq(lfile_read(lfile, &string), 0);
	ck_assert(string == NULL);

	lfile_close(lfile);
}
END_TEST

START_TEST(file_line_null_chara)
{
	struct line_file *lfile;
	char *string;

	ck_assert_int_eq(lfile_open("line_file/error.txt", &lfile), 0);

	ck_assert_int_eq(lfile_read(lfile, &string), 0);
	ck_assert_str_eq(string, "This is a normal line.");
	free(string);

	ck_assert_int_eq(lfile_read(lfile, &string), -EINVAL);

	lfile_close(lfile);
}
END_TEST

Suite *ghostbusters_suite(void)
{
	Suite *suite;
	TCase *core, *limits, *errors;

	core = tcase_create("Core");
	tcase_add_test(core, file_line_normal);

	limits = tcase_create("Limits");
	tcase_add_test(limits, file_line_empty);

	errors = tcase_create("Errors");
	tcase_add_test(errors, file_line_null_chara);

	suite = suite_create("lfile_read()");
	suite_add_tcase(suite, core);
	suite_add_tcase(suite, limits);
	suite_add_tcase(suite, errors);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = ghostbusters_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
