#include <check.h>

#include "config.c"
#include "rtr/pdu_sender.c"

static void
ck_intervals(uint32_t validation, uint32_t expire)
{
	uint32_t refresh;
	uint32_t retry;

	fortcfg.interval = validation;
	fortcfg.rtr.expire = expire;

	refresh = get_refresh();
	retry = get_retry();

	ck_assert_uint_le(1, refresh);
	ck_assert_uint_le(refresh, 86400);
	ck_assert_uint_le(1, retry);
	ck_assert_uint_le(retry, 7200);
	ck_assert_uint_lt(refresh, expire);
	ck_assert_uint_lt(retry, expire);
}

START_TEST(test_interval_limits)
{
	const uint32_t REFRESH_MIN = 1;
	const uint32_t REFRESH_MAX = 86400;
	const uint32_t REFRESH_DEFAULT = 3600;

	ck_intervals(REFRESH_MIN, EXPIRE_MIN);
	ck_intervals(REFRESH_MIN, EXPIRE_MAX);
	ck_intervals(REFRESH_MIN, EXPIRE_DEFAULT);

	ck_intervals(REFRESH_MAX, EXPIRE_MIN);
	ck_intervals(REFRESH_MAX, EXPIRE_MAX);
	ck_intervals(REFRESH_MAX, EXPIRE_DEFAULT);

	ck_intervals(REFRESH_DEFAULT, EXPIRE_MIN);
	ck_intervals(REFRESH_DEFAULT, EXPIRE_MAX);
	ck_intervals(REFRESH_DEFAULT, EXPIRE_DEFAULT);

	ck_intervals(VALIDATION_INTERVAL_MIN, EXPIRE_MIN);
	ck_intervals(VALIDATION_INTERVAL_MIN, EXPIRE_MAX);
	ck_intervals(VALIDATION_INTERVAL_MIN, EXPIRE_DEFAULT);

	ck_intervals(VALIDATION_INTERVAL_MAX, EXPIRE_MIN);
	ck_intervals(VALIDATION_INTERVAL_MAX, EXPIRE_MAX);
	ck_intervals(VALIDATION_INTERVAL_MAX, EXPIRE_DEFAULT);

	ck_intervals(VALIDATION_INTERVAL_DEFAULT, EXPIRE_MIN);
	ck_intervals(VALIDATION_INTERVAL_DEFAULT, EXPIRE_MAX);
	ck_intervals(VALIDATION_INTERVAL_DEFAULT, EXPIRE_DEFAULT);
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Intervals");
	tcase_add_test(core, test_interval_limits);

	suite = suite_create("PDU Sender");
	suite_add_tcase(suite, core);
	return suite;
}

int
main(void)
{
	SRunner *runner;
	int tests_failed;

	runner = srunner_create(create_suite());
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
