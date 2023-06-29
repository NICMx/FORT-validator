#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "types/address.c"

/* Tests */

static void
test_range4(uint32_t min, uint32_t max, bool valid)
{
	struct ipv4_range range = {
	    .min.s_addr = htonl(min),
	    .max.s_addr = htonl(max),
	};
	ck_assert_int_eq(valid ? 0 : -EINVAL, check_encoding4(&range));
}

START_TEST(check_encoding4_test)
{
	test_range4(0x00000000, 0x00000000, false);
	test_range4(0x12345678, 0x12345678, false);
	test_range4(0xFFFFFFFF, 0xFFFFFFFF, false);
	test_range4(0x00000000, 0xFFFFFFFF, false);
	test_range4(0x00000000, 0x00000001, false);
	test_range4(0x11000000, 0x11001000, true);
	test_range4(0x11000000, 0x1100FFFF, false);
	test_range4(0x11000000, 0x1100F1FF, true);

}
END_TEST

static void
test_range6(uint32_t a1a, uint32_t a1b, uint32_t a1c, uint32_t a1d,
    uint32_t a2a, uint32_t a2b, uint32_t a2c, uint32_t a2d,
    bool valid)
{
	struct ipv6_range range;

	addr6_set_quadrant(&range.min, 0, a1a);
	addr6_set_quadrant(&range.min, 1, a1b);
	addr6_set_quadrant(&range.min, 2, a1c);
	addr6_set_quadrant(&range.min, 3, a1d);
	addr6_set_quadrant(&range.max, 0, a2a);
	addr6_set_quadrant(&range.max, 1, a2b);
	addr6_set_quadrant(&range.max, 2, a2c);
	addr6_set_quadrant(&range.max, 3, a2d);

	ck_assert_int_eq(valid ? 0 : -EINVAL, check_encoding6(&range));
}

START_TEST(check_encoding6_test)
{
	test_range6(0x00000000, 0x00000000, 0x00000000, 0x00000000,
	            0x00000000, 0x00000000, 0x00000000, 0x00000000,
	            false);
	test_range6(0x12345678, 0x12345678, 0x12345678, 0x12345678,
	            0x12345678, 0x12345678, 0x12345678, 0x12345678,
	            false);
	test_range6(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            false);

	test_range6(0x00000000, 0x00000000, 0x00000000, 0x00000000,
	            0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            false);
	test_range6(0x00000000, 0x00000000, 0x00000000, 0x00000000,
	            0x00000000, 0x00000000, 0x00000000, 0x00000001,
	            false);

	/* Matching most significant bits stop on the first quadrant */
	test_range6(0x00001000, 0x00000000, 0x00000000, 0x00000000,
	            0x00001FFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            false);

	test_range6(0x00001010, 0x00000000, 0x00000000, 0x00000000,
	            0x00001FFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00001000, 0x00000000, 0x00000000,
	            0x00001FFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00000000, 0x00001000, 0x00000000,
	            0x00001FFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00000000, 0x00000000, 0x00001000,
	            0x00001FFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            true);

	test_range6(0x00001000, 0x00000000, 0x00000000, 0x00000000,
	            0x00001F0F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00000000, 0x00000000, 0x00000000,
	            0x00001FFF, 0xFF0FFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00000000, 0x00000000, 0x00000000,
	            0x00001FFF, 0xFFFFFFFF, 0xFFFFF0FF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00000000, 0x00000000, 0x00000000,
	            0x00001FFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFF0FF,
	            true);

	/* Matching most significant bits stop on the second quadrant */
	test_range6(0x00001000, 0x00001000, 0x00000000, 0x00000000,
	            0x00001000, 0x00001FFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            false);

	test_range6(0x00001000, 0x00001010, 0x00000000, 0x00000000,
	            0x00001000, 0x00001FFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00001000, 0x00001000, 0x00000000,
	            0x00001000, 0x00001FFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00001000, 0x00000000, 0x00001000,
	            0x00001000, 0x00001FFF, 0xFFFFFFFF, 0xFFFFFFFF,
	            true);

	test_range6(0x00001000, 0x00001000, 0x00000000, 0x00000000,
	            0x00001000, 0x00001F0F, 0xFFFFFFFF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00001000, 0x00000000, 0x00000000,
	            0x00001000, 0x00001FFF, 0xFFFFF0FF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00001000, 0x00000000, 0x00000000,
	            0x00001000, 0x00001FFF, 0xFFFFFFFF, 0xFFFFF0FF,
	            true);

	/* Matching most significant bits stop on the third quadrant */
	test_range6(0x00001000, 0x00001000, 0x00001000, 0x00000000,
	            0x00001000, 0x00001000, 0x00001FFF, 0xFFFFFFFF,
	            false);

	test_range6(0x00001000, 0x00001000, 0x00001010, 0x00000000,
	            0x00001000, 0x00001000, 0x00001FFF, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00001000, 0x00001000, 0x00001000,
	            0x00001000, 0x00001000, 0x00001FFF, 0xFFFFFFFF,
	            true);

	test_range6(0x00001000, 0x00001000, 0x00001000, 0x00000000,
	            0x00001000, 0x00001000, 0x00001F0F, 0xFFFFFFFF,
	            true);
	test_range6(0x00001000, 0x00001000, 0x00001000, 0x00000000,
	            0x00001000, 0x00001000, 0x00001FFF, 0xFFFFF0FF,
	            true);

	/* Matching most significant bits stop on the fourth quadrant */
	test_range6(0x00001000, 0x00001000, 0x00001000, 0x00001000,
	            0x00001000, 0x00001000, 0x00001000, 0x00001FFF,
	            false);

	test_range6(0x00001000, 0x00001000, 0x00001000, 0x00001010,
	            0x00001000, 0x00001000, 0x00001000, 0x00001FFF,
	            true);

	test_range6(0x00001000, 0x00001000, 0x00001000, 0x00001000,
	            0x00001000, 0x00001000, 0x00001000, 0x00001F0F,
	            true);
}
END_TEST

Suite *address_load_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, check_encoding4_test);
	tcase_add_test(core, check_encoding6_test);

	suite = suite_create("Encoding checking");
	suite_add_tcase(suite, core);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = address_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
