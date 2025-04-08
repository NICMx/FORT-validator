#include "common.c"

#include <check.h>

#include "alloc.c"
#include "mock.c"

static const long MS2NS = 1000000L;

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

#define init_ts(ts, s, ns)			\
	ts.tv_sec = s;				\
	ts.tv_nsec = ns

#define ck_ts(ts, s, ns)			\
	ck_assert_int_eq(s, ts.tv_sec);		\
	ck_assert_int_eq(ns, ts.tv_nsec)

START_TEST(test_ts_normalize)
{
	struct timespec ts;

	init_ts(ts, 100, 0);
	ts_normalize(&ts);
	ck_ts(ts, 100, 0);

	init_ts(ts, 100, 999999999);
	ts_normalize(&ts);
	ck_ts(ts, 100, 999999999);

	init_ts(ts, 100, 1000 * MS2NS);
	ts_normalize(&ts);
	ck_ts(ts, 101, 0);

	init_ts(ts, 100, 2500 * MS2NS);
	ts_normalize(&ts);
	ck_ts(ts, 102, 500 * MS2NS);

	init_ts(ts, 100, -1);
	ts_normalize(&ts);
	ck_ts(ts, 99, 999999999);

	init_ts(ts, 100, -5000 * MS2NS);
	ts_normalize(&ts);
	ck_ts(ts, 95, 0);

	init_ts(ts, 100, -5000 * MS2NS - 2);
	ts_normalize(&ts);
	ck_ts(ts, 94, 999999998);
}
END_TEST

START_TEST(test_ts_cmp)
{
	struct timespec t1, t2;

	/* Same second */
	init_ts(t1, 100, 500);
	init_ts(t2, 100, 500);
	ck_assert_int_eq(0, ts_cmp(&t1, &t2));
	ck_assert_int_eq(0, ts_cmp(&t2, &t1));

	t1.tv_nsec = 1000;
	t2.tv_nsec = 9000;
	ck_assert(ts_cmp(&t1, &t2) < 0);
	ck_assert(ts_cmp(&t2, &t1) > 0);

	t1.tv_nsec = 9000;
	t2.tv_nsec = 1000;
	ck_assert(ts_cmp(&t1, &t2) > 0);
	ck_assert(ts_cmp(&t2, &t1) < 0);

	/* t1 < t2 by second */
	init_ts(t1, 100, 500);
	init_ts(t2, 101, 500);
	ck_assert(ts_cmp(&t1, &t2) < 0);
	ck_assert(ts_cmp(&t2, &t1) > 0);

	t1.tv_nsec = 1000;
	t2.tv_nsec = 9000;
	ck_assert(ts_cmp(&t1, &t2) < 0);
	ck_assert(ts_cmp(&t2, &t1) > 0);

	t1.tv_nsec = 9000;
	t2.tv_nsec = 1000;
	ck_assert(ts_cmp(&t1, &t2) < 0);
	ck_assert(ts_cmp(&t2, &t1) > 0);

	/* t1 > t2 by second */
	init_ts(t1, 100, 500);
	init_ts(t2, 99, 500);
	ck_assert(ts_cmp(&t1, &t2) > 0);
	ck_assert(ts_cmp(&t2, &t1) < 0);

	t1.tv_nsec = 1000;
	t2.tv_nsec = 9000;
	ck_assert(ts_cmp(&t1, &t2) > 0);
	ck_assert(ts_cmp(&t2, &t1) < 0);

	t1.tv_nsec = 9000;
	t2.tv_nsec = 1000;
	ck_assert(ts_cmp(&t1, &t2) > 0);
	ck_assert(ts_cmp(&t2, &t1) < 0);
}
END_TEST

START_TEST(test_ts_delta)
{
	struct timespec t1, t2;

	init_ts(t1, 100, 0);
	init_ts(t2, 100, 2 * MS2NS);
	ck_assert_int_eq(2, ts_delta(&t1, &t2));
	ck_assert_int_eq(-2, ts_delta(&t2, &t1));

	init_ts(t1, 100, 0);
	init_ts(t2, 100, -2 * MS2NS);
	ck_assert_int_eq(-2, ts_delta(&t1, &t2));
	ck_assert_int_eq(2, ts_delta(&t2, &t1));

	init_ts(t1, 50, 0);
	init_ts(t2, 100, 0);
	ck_assert_int_eq(50000, ts_delta(&t1, &t2));
	ck_assert_int_eq(-50000, ts_delta(&t2, &t1));

	init_ts(t1, -10, 0);
	init_ts(t2, 10, 0);
	ck_assert_int_eq(20000, ts_delta(&t1, &t2));
	ck_assert_int_eq(-20000, ts_delta(&t2, &t1));

	init_ts(t1, -10, 1 * MS2NS);	/* -9999ms */
	init_ts(t2, 10, 2 * MS2NS);	/* 10002ms */
	ck_assert_int_eq(20001, ts_delta(&t1, &t2));
	ck_assert_int_eq(-20001, ts_delta(&t2, &t1));
}
END_TEST

START_TEST(test_ts_add)
{
	struct timespec src, dst;

	init_ts(src, 100, 0);		/* 100 */
	ts_add(&dst, &src, 100);	/* +0.1 */
	ck_ts(dst, 100, 100 * MS2NS);	/* 100.1 */

	ts_add(&dst, &src, -100);	/* -0.1 */
	ck_ts(dst, 99, 900 * MS2NS);	/* 99.9 */

	init_ts(src, 100, 50 * MS2NS);	/* 100.05 */
	ts_add(&dst, &src, 100);	/* +0.1 */
	ck_ts(dst, 100, 150 * MS2NS);	/* 100.15 */

	ts_add(&dst, &src, -100);	/* -0.1 */
	ck_ts(dst, 99, 950 * MS2NS);	/* 99.95 */

	init_ts(src, 100, 0);		/* 100 */
	ts_add(&dst, &src, 10000);	/* +10 */
	ck_ts(dst, 110, 0);		/* 110 */

	ts_add(&dst, &src, -10000);	/* -10 */
	ck_ts(dst, 90, 0);		/* 90 */

	init_ts(src, 89, 123409876);	/* 89.1234 */
	ts_add(&dst, &src, 98765);	/* +98.765 */
	ck_ts(dst, 187, 888409876);	/* 187.8884 */

	init_ts(src, 9, 123409876);	/* 9.1234 */
	ts_add(&dst, &src, -12345);	/* -12.345 */
	ck_ts(dst, -4, 778409876);	/* -3.2216 (-4+0.7784) */
}
END_TEST

static Suite *create_suite(void)
{
	Suite *suite;
	TCase *timet, *ts;

	timet = tcase_create("time_t");
	tcase_add_test(timet, test_tt);

	ts = tcase_create("timespec");
	tcase_add_test(ts, test_ts_normalize);
	tcase_add_test(ts, test_ts_cmp);
	tcase_add_test(ts, test_ts_delta);
	tcase_add_test(ts, test_ts_add);

	suite = suite_create("commons");
	suite_add_tcase(suite, timet);
	suite_add_tcase(suite, ts);
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
