#include "address.c"

#include <check.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

START_TEST(load_normal)
{

}
END_TEST

static void
test_get_address_from_string(char *text_prefix)
{
	struct ipv4_prefix prefix;
	const char *result;
	int error;
	char buffer[INET_ADDRSTRLEN];

	error = prefix4_decode(text_prefix, &prefix);
	if (error)
		return;

	result = addr2str4(&prefix.addr, buffer);

	ck_assert_str_eq(text_prefix, result);
}

START_TEST(address_test_get_addr)
{
	char *text;
	text = "198.248.146.0";

	test_get_address_from_string(text);

}
END_TEST

Suite *address_load_suite(void)
{
	Suite *suite;
	TCase *core, *test_get_address;

	core = tcase_create("Core");
	tcase_add_test(core, load_normal);

	test_get_address = tcase_create("test_get_address");
	tcase_add_test(test_get_address, address_test_get_addr);

	suite = suite_create("address_test()");
	suite_add_tcase(suite, core);
	suite_add_tcase(suite, test_get_address);

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
