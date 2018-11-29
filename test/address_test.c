#include "address.h"

#include <check.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

static bool
p4test(uint32_t a1, int l1, uint32_t a2, int l2)
{
	struct ipv4_prefix a, b;

	a.addr.s_addr = htonl(a1);
	a.len = l1;
	b.addr.s_addr = htonl(a2);
	b.len = l2;

	return prefix4_contains(&a, &b);
}

START_TEST(test_prefix4_contains)
{
	unsigned int i;

	/* Prefix-only tests */

	ck_assert_int_eq(false, p4test(0x12345678u, 32, 0x12345677u, 32));
	ck_assert_int_eq(true,  p4test(0x12345678u, 32, 0x12345678u, 32));
	ck_assert_int_eq(false, p4test(0x12345678u, 32, 0x12345679u, 32));

	ck_assert_int_eq(false, p4test(0x01020304u, 30, 0x01020303u, 32));
	ck_assert_int_eq(true,  p4test(0x01020304u, 30, 0x01020304u, 32));
	ck_assert_int_eq(true,  p4test(0x01020304u, 30, 0x01020305u, 32));
	ck_assert_int_eq(true,  p4test(0x01020304u, 30, 0x01020306u, 32));
	ck_assert_int_eq(true,  p4test(0x01020304u, 30, 0x01020307u, 32));
	ck_assert_int_eq(false, p4test(0x01020304u, 30, 0x01020308u, 32));

	ck_assert_int_eq(true,  p4test(0x00000000u,  0, 0x00000000u, 32));
	ck_assert_int_eq(true,  p4test(0x00000000u,  0, 0x12345678u, 32));
	ck_assert_int_eq(true,  p4test(0x00000000u,  0, 0xFFFFFFFFu, 32));

	/* Length-only tests */

	for (i = 0; i < 33; i++)
		ck_assert_int_eq(true, p4test(0, i, 0, 32));
	for (i = 0; i < 32; i++)
		ck_assert_int_eq(false, p4test(0, 32, 0, i));
	for (i = 0; i < 33; i++)
		ck_assert_int_eq(true, p4test(0, 0, 0, i));
	for (i = 1; i < 33; i++)
		ck_assert_int_eq(false, p4test(0, i, 0, 0));
}
END_TEST

static void
p6init(struct ipv6_prefix *p, uint32_t q1, uint32_t q2, uint32_t q3,
    uint32_t q4, int len)
{
	p->addr.s6_addr32[0] = htonl(q1);
	p->addr.s6_addr32[1] = htonl(q2);
	p->addr.s6_addr32[2] = htonl(q3);
	p->addr.s6_addr32[3] = htonl(q4);
	p->len = len;
}

START_TEST(test_prefix6_contains)
{
	struct ipv6_prefix a, b;

	p6init(&a, 0, 0, 0, 0, 128);
	p6init(&b, 0, 0, 0, 0, 128);

	/* Length-only tests */

	for (a.len = 0; a.len < 129; a.len++)
		ck_assert_int_eq(true, prefix6_contains(&a, &b));

	a.len = 128;
	for (b.len = 0; b.len < 128; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	a.len = 0;
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(true, prefix6_contains(&a, &b));

	b.len = 0;
	for (a.len = 1; a.len < 129; a.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	/* Full quadrants */

	/* pl = 0 */
	p6init(&a, 0, 0, 0, 0, 0);
	p6init(&b, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 128);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));
	/* Others were already tested above. */

	/* pl = 32 */
	p6init(&a, 0x13131313u, 0, 0, 0, 32);
	p6init(&b, 0x13131313u, 0, 0, 0, 32);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x13131313u, 0xffffffffu, 0xffffffffu, 0xffffffffu, 128);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x13151313u, 0xffffffffu, 0xffffffffu, 0xffffffffu, 128);
	ck_assert_int_eq(false, prefix6_contains(&a, &b));

	/* pl = 64 */
	p6init(&a, 0x13131313u, 0x13131313u, 0, 0, 64);
	p6init(&b, 0x13131313u, 0x13131313u, 0, 0, 64);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x13131313u, 0x13131313u, 0xffffffffu, 0xffffffffu, 128);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x13151313u, 0x13131313u, 0, 0, 128);
	ck_assert_int_eq(false, prefix6_contains(&a, &b));
	p6init(&b, 0x13131313u, 0x13151313u, 0xffffffffu, 0xffffffffu, 128);
	ck_assert_int_eq(false, prefix6_contains(&a, &b));

	/* pl = 96 */
	p6init(&a, 0x13131313u, 0x13131313u, 0x13131313u, 0, 96);
	p6init(&b, 0x13131313u, 0x13131313u, 0x13131313u, 0, 96);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x13131313u, 0x13131313u, 0x13131313u, 0xffffffffu, 128);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x13151313u, 0x13131313u, 0x13131313u, 0, 128);
	ck_assert_int_eq(false, prefix6_contains(&a, &b));
	p6init(&b, 0x13131313u, 0x13151313u, 0x13131313u, 0x12345678u, 128);
	ck_assert_int_eq(false, prefix6_contains(&a, &b));
	p6init(&b, 0x13131313u, 0x13131313u, 0x13151313u, 0xffffffffu, 128);
	ck_assert_int_eq(false, prefix6_contains(&a, &b));

	/* Try different prefixes in the same quadrant*/

	p6init(&a, 0x20010000u, 0, 0, 0, 16);
	p6init(&b, 0x20000000u, 0, 0, 0, 0);
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	p6init(&a, 0, 0x20010000u, 0, 0, 48);
	p6init(&b, 0, 0x20000000u, 0, 0, 0);
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	p6init(&a, 0, 0, 0x20010000u, 0, 80);
	p6init(&b, 0, 0, 0x20000000u, 0, 0);
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	p6init(&a, 0, 0, 0, 0x20010000u, 112);
	p6init(&b, 0, 0, 0, 0x20000000u, 0);
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	/* Try different prefixes in different quadrants */

	/* q2 */
	p6init(&a, 1, 0x20010000u, 0, 0, 48);
	p6init(&b, 0, 0x20010000u, 0, 0, 0);
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	/* q3 */
	p6init(&a, 1, 0, 0x20010000u, 0, 80);
	p6init(&b, 0, 0, 0x20000000u, 0, 0);
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	p6init(&a, 0, 1, 0x20010000u, 0, 80);
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	/* q4 */
	p6init(&a, 1, 0, 0, 0x20010000u, 112);
	p6init(&b, 0, 0, 0, 0x20000000u, 0);
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	p6init(&a, 0, 1, 0, 0x20010000u, 112);
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	p6init(&a, 0, 0, 1, 0x20010000u, 112);
	for (b.len = 0; b.len < 129; b.len++)
		ck_assert_int_eq(false, prefix6_contains(&a, &b));

	/* Try actually containing prefixes */

	/* q1 */
	p6init(&a, 0x20010000u, 0, 0, 0, 16);
	p6init(&b, 0x20010000u, 0, 0, 0, 16);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x2001ffffu, 0, 0, 0, 32);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x2001ffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 128);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	/* q2 */
	p6init(&a, 0x20010000u, 0x20010000u, 0, 0, 48);
	p6init(&b, 0x20010000u, 0x20010000u, 0, 0, 48);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x20010000u, 0x2001ffffu, 0, 0, 64);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x20010000u, 0x2001ffffu, 0xffffffffu, 0xffffffffu, 128);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	/* q3 */
	p6init(&a, 0x20010000u, 0x20010000u, 0x20010000u, 0, 80);
	p6init(&b, 0x20010000u, 0x20010000u, 0x20010000u, 0, 80);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x20010000u, 0x20010000u, 0x2001ffffu, 0, 96);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x20010000u, 0x20010000u, 0x2001ffffu, 0xffffffff, 128);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	/* q4 */
	p6init(&a, 0x20010000u, 0x20010000u, 0x20010000u, 0x20010000, 112);
	p6init(&b, 0x20010000u, 0x20010000u, 0x20010000u, 0x20010000, 112);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));

	p6init(&b, 0x20010000u, 0x20010000u, 0x20010000u, 0x2001ffff, 128);
	ck_assert_int_eq(true, prefix6_contains(&a, &b));
}
END_TEST

Suite *lfile_read_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, test_prefix6_contains);
	tcase_add_test(core, test_prefix4_contains);

	suite = suite_create("address");
	suite_add_tcase(suite, core);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = lfile_read_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
