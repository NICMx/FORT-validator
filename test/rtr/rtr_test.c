#include <check.h>

#include "alloc.c"
#include "mock.c"
#include "rtr/rtr.c"

#define ck_parse(in, addr, serv)				\
	ck_assert_int_eq(0, parse_address(in, &_addr, &_serv));	\
	ck_assert_str_eq(addr, _addr);				\
	ck_assert_str_eq(serv, _serv);				\
	free(_addr);						\
	free(_serv);

#define ck_parse_fail(in) \
	ck_assert_int_eq(EINVAL, parse_address(in, &_addr, &_serv));

START_TEST(test_parse_address)
{
	char *_addr, *_serv;

	fortcfg.rtr.port = "1234";

	ck_assert_int_eq(0, parse_address(NULL, &_addr, &_serv));
	ck_assert_ptr_eq(NULL, _addr);
	ck_assert_str_eq("1234", _serv);
	free(_serv);

	ck_parse("192.0.2.1", "192.0.2.1", "1234");
	ck_parse("192.0.2.2:", "192.0.2.2", "1234");

	ck_parse("2001:db8::1", "2001:db8::1", "1234");

	ck_parse("hostname", "hostname", "1234");
	ck_parse("hostname:4321", "hostname", "4321");
	ck_parse("multi.host.name", "multi.host.name", "1234");
	ck_parse("multi.host.name:4321", "multi.host.name", "4321");

	ck_parse_fail("[192.0.2.3");
	ck_parse_fail("[192.0.2.4:4321");
	ck_parse_fail("[2001:db8::2");
	ck_parse_fail("[2001:db8::3:4321");
	ck_parse_fail("[hostname");
	ck_parse_fail("[multi.host.name:4321");

	ck_parse_fail("[192.0.2.5]1234");
	ck_parse_fail("[192.0.2.6][");
	ck_parse_fail("[192.0.2.7]]");

	ck_parse("[192.0.2.8]", "192.0.2.8", "1234");
	ck_parse("[192.0.2.9]:", "192.0.2.9", "1234");
	ck_parse("[192.0.2.10]:4321", "192.0.2.10", "4321");

	ck_parse("[2001:db8::4]", "2001:db8::4", "1234");
	ck_parse("[2001:db8::5]:", "2001:db8::5", "1234");
	ck_parse("[2001:db8::6]:4321", "2001:db8::6", "4321");

	ck_parse("[multi.host.name]", "multi.host.name", "1234");
	ck_parse("[multi.host.name]:", "multi.host.name", "1234");
	ck_parse("[multi.host.name]:4321", "multi.host.name", "4321");
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Address parsing");
	tcase_add_test(core, test_parse_address);

	suite = suite_create("RTR");
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
