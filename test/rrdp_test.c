#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "alloc.c"
#include "mock.c"
#include "rrdp.c"

/* Mocks */

MOCK_ABORT_PTR(uri_refget, rpki_uri, struct rpki_uri *uri)
MOCK_ABORT_VOID(uri_refput, struct rpki_uri *uri)
__MOCK_ABORT(uri_get_local, char const *, NULL, struct rpki_uri *uri)
MOCK(uri_val_get_printable, char const *, "uri", struct rpki_uri *uri)
MOCK_ABORT_VOID(fnstack_push_uri, struct rpki_uri *uri)
MOCK_ABORT_VOID(fnstack_pop, void)

/* Mocks end */

#define END 0xFFFF

static void
add_serials(struct notification_deltas *deltas, ...)
{
	struct notification_delta delta = { 0 };
	va_list vl;

	va_start(vl, deltas);
	while ((delta.serial = va_arg(vl, unsigned long)) != END)
		notification_deltas_add(deltas, &delta);
	va_end(vl);
}

static void
validate_serials(struct notification_deltas *deltas, ...)
{
	unsigned long serial;
	unsigned int i;
	va_list vl;

	va_start(vl, deltas);

	i = 0;
	while ((serial = va_arg(vl, unsigned long)) != END) {
		ck_assert_uint_eq(serial, deltas->array[i].serial);
		i++;
	}

	va_end(vl);
}

START_TEST(test_notification_deltas_sort)
{
	struct notification_deltas deltas;

	notification_deltas_init(&deltas);
	ck_assert_int_eq(0, notification_deltas_sort(&deltas, 0));
	ck_assert_int_eq(0, notification_deltas_sort(&deltas, 1));
	ck_assert_int_eq(0, notification_deltas_sort(&deltas, 2));

	add_serials(&deltas, 0, END);
	ck_assert_int_eq(0, notification_deltas_sort(&deltas, 0));
	validate_serials(&deltas, 0, END);

	ck_assert_int_eq(-EINVAL, notification_deltas_sort(&deltas, 2));
	ck_assert_int_eq(-EINVAL, notification_deltas_sort(&deltas, 1));

	add_serials(&deltas, 1, 2, 3, END);
	ck_assert_int_eq(0, notification_deltas_sort(&deltas, 3));
	validate_serials(&deltas, 0, 1, 2, 3, END);

	ck_assert_int_eq(-EINVAL, notification_deltas_sort(&deltas, 4));
	ck_assert_int_eq(-EINVAL, notification_deltas_sort(&deltas, 2));

	notification_deltas_cleanup(&deltas, NULL);
	notification_deltas_init(&deltas);

	add_serials(&deltas, 3, 0, 1, 2, END);
	ck_assert_int_eq(0, notification_deltas_sort(&deltas, 3));
	validate_serials(&deltas, 0, 1, 2, 3, END);

	notification_deltas_cleanup(&deltas, NULL);
	notification_deltas_init(&deltas);

	add_serials(&deltas, 4, 3, 2, 1, 0, END);
	ck_assert_int_eq(0, notification_deltas_sort(&deltas, 4));
	validate_serials(&deltas, 0, 1, 2, 3, 4, END);

	ck_assert_int_eq(-EINVAL, notification_deltas_sort(&deltas, 5));
	ck_assert_int_eq(-EINVAL, notification_deltas_sort(&deltas, 3));

	notification_deltas_cleanup(&deltas, NULL);
}
END_TEST

Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *validate;

	validate = tcase_create("Validate");
	tcase_add_test(validate, test_notification_deltas_sort);

	suite = suite_create("xml_test()");
	suite_add_tcase(suite, validate);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = xml_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
