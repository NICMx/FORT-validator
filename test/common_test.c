#include "common.c"

#include <check.h>

#include "alloc.c"
#include "mock.c"

START_TEST(test_tt)
{
	char str[FORT_TS_LEN + 1];
	time_t tt;

	ck_assert_int_eq(0, str2time("2024-03-14T17:51:16Z", &tt));

	memset(str, 'f', sizeof(str));
	ck_assert_int_eq(0, time2str(tt, str));
	ck_assert_str_eq("2024-03-14T17:51:16Z", str);
	ck_assert_int_eq('f', str[FORT_TS_LEN]); /* Tests FORT_TS_LEN. */
}
END_TEST

static Suite *common_load_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("utils");
	tcase_add_test(core, test_tt);

	suite = suite_create("commons");
	suite_add_tcase(suite, core);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = common_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
