#include <check.h>
#include <stdlib.h>

#include "types/serial.c"

START_TEST(pivot_0)
{
	/* Pivot: Zero */
	ck_assert_int_eq(false, serial_lt(0, 0));

	ck_assert_int_eq(true, serial_lt(0, 1));
	ck_assert_int_eq(true, serial_lt(0, 2));
	ck_assert_int_eq(true, serial_lt(0, 3));
	ck_assert_int_eq(true, serial_lt(0, 4));

	ck_assert_int_eq(true, serial_lt(0, 0x7FFFFFFCu));
	ck_assert_int_eq(true, serial_lt(0, 0x7FFFFFFDu));
	ck_assert_int_eq(true, serial_lt(0, 0x7FFFFFFEu));
	ck_assert_int_eq(true, serial_lt(0, 0x7FFFFFFFu));

	ck_assert_int_eq(false, serial_lt(0, 0x80000001u));
	ck_assert_int_eq(false, serial_lt(0, 0x80000002u));
	ck_assert_int_eq(false, serial_lt(0, 0x80000003u));
	ck_assert_int_eq(false, serial_lt(0, 0x80000004u));

	ck_assert_int_eq(false, serial_lt(0, 0xFFFFFFFCu));
	ck_assert_int_eq(false, serial_lt(0, 0xFFFFFFFDu));
	ck_assert_int_eq(false, serial_lt(0, 0xFFFFFFFEu));
	ck_assert_int_eq(false, serial_lt(0, 0xFFFFFFFFu));
}
END_TEST

START_TEST(pivot_mid)
{
	ck_assert_int_eq(false, serial_lt(0x80000000u, 0x80000000u));

	ck_assert_int_eq(true, serial_lt(0x80000000u, 0x80000001u));
	ck_assert_int_eq(true, serial_lt(0x80000000u, 0x80000002u));
	ck_assert_int_eq(true, serial_lt(0x80000000u, 0x80000003u));
	ck_assert_int_eq(true, serial_lt(0x80000000u, 0x80000004u));

	ck_assert_int_eq(true, serial_lt(0x80000000u, 0xFFFFFFFCu));
	ck_assert_int_eq(true, serial_lt(0x80000000u, 0xFFFFFFFDu));
	ck_assert_int_eq(true, serial_lt(0x80000000u, 0xFFFFFFFEu));
	ck_assert_int_eq(true, serial_lt(0x80000000u, 0xFFFFFFFFu));

	ck_assert_int_eq(false, serial_lt(0x80000000u, 1));
	ck_assert_int_eq(false, serial_lt(0x80000000u, 2));
	ck_assert_int_eq(false, serial_lt(0x80000000u, 3));
	ck_assert_int_eq(false, serial_lt(0x80000000u, 4));

	ck_assert_int_eq(false, serial_lt(0x80000000u, 0x7FFFFFFCu));
	ck_assert_int_eq(false, serial_lt(0x80000000u, 0x7FFFFFFDu));
	ck_assert_int_eq(false, serial_lt(0x80000000u, 0x7FFFFFFEu));
	ck_assert_int_eq(false, serial_lt(0x80000000u, 0x7FFFFFFFu));
}
END_TEST

START_TEST(pivot_max)
{
	ck_assert_int_eq(false, serial_lt(0xFFFFFFFFu, 0xFFFFFFFFu));

	ck_assert_int_eq(true, serial_lt(0xFFFFFFFFu, 1));
	ck_assert_int_eq(true, serial_lt(0xFFFFFFFFu, 2));
	ck_assert_int_eq(true, serial_lt(0xFFFFFFFFu, 3));
	ck_assert_int_eq(true, serial_lt(0xFFFFFFFFu, 4));

	ck_assert_int_eq(true, serial_lt(0xFFFFFFFFu, 0x7FFFFFFBu));
	ck_assert_int_eq(true, serial_lt(0xFFFFFFFFu, 0x7FFFFFFCu));
	ck_assert_int_eq(true, serial_lt(0xFFFFFFFFu, 0x7FFFFFFDu));
	ck_assert_int_eq(true, serial_lt(0xFFFFFFFFu, 0x7FFFFFFEu));

	ck_assert_int_eq(false, serial_lt(0xFFFFFFFFu, 0x80000000u));
	ck_assert_int_eq(false, serial_lt(0xFFFFFFFFu, 0x80000001u));
	ck_assert_int_eq(false, serial_lt(0xFFFFFFFFu, 0x80000002u));
	ck_assert_int_eq(false, serial_lt(0xFFFFFFFFu, 0x80000003u));

	ck_assert_int_eq(false, serial_lt(0xFFFFFFFFu, 0xFFFFFFFBu));
	ck_assert_int_eq(false, serial_lt(0xFFFFFFFFu, 0xFFFFFFFCu));
	ck_assert_int_eq(false, serial_lt(0xFFFFFFFFu, 0xFFFFFFFDu));
	ck_assert_int_eq(false, serial_lt(0xFFFFFFFFu, 0xFFFFFFFEu));
}
END_TEST

START_TEST(rfc1982_section_5_2)
{
	const serial_t multiplier = 0xFFFFFFFFu / 256;
	/*
	 * These are the examples from rfc1982#section-5.2, adjusted to the
	 * larger SERIAL_BITS.
	 */
	const serial_t N0 = 0;
	const serial_t N1 = 1 * multiplier;
	const serial_t N44 = 44 * multiplier;
	const serial_t N100 = 100 * multiplier;
	const serial_t N200 = 200 * multiplier;
	const serial_t N255 = 255 * multiplier;

	ck_assert_int_eq(true, serial_lt(N0, N1));
	ck_assert_int_eq(true, serial_lt(N0, N44));
	ck_assert_int_eq(true, serial_lt(N0, N100));
	ck_assert_int_eq(true, serial_lt(N44, N100));
	ck_assert_int_eq(true, serial_lt(N100, N200));
	ck_assert_int_eq(true, serial_lt(N200, N255));
	ck_assert_int_eq(true, serial_lt(N255, N0));
	ck_assert_int_eq(true, serial_lt(N255, N100));
	ck_assert_int_eq(true, serial_lt(N200, N0));
	ck_assert_int_eq(true, serial_lt(N200, N44));

	ck_assert_int_eq(false, serial_lt(N1, N0));
	ck_assert_int_eq(false, serial_lt(N44, N0));
	ck_assert_int_eq(false, serial_lt(N100, N0));
	ck_assert_int_eq(false, serial_lt(N100, N44));
	ck_assert_int_eq(false, serial_lt(N200, N100));
	ck_assert_int_eq(false, serial_lt(N255, N200));
	ck_assert_int_eq(false, serial_lt(N0, N255));
	ck_assert_int_eq(false, serial_lt(N100, N255));
	ck_assert_int_eq(false, serial_lt(N0, N200));
	ck_assert_int_eq(false, serial_lt(N44, N200));
}
END_TEST

Suite *serial_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, pivot_0);
	tcase_add_test(core, pivot_mid);
	tcase_add_test(core, pivot_max);
	tcase_add_test(core, rfc1982_section_5_2);

	suite = suite_create("serial");
	suite_add_tcase(suite, core);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = serial_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
