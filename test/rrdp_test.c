#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "alloc.c"
#include "mock.c"
#include "rrdp.c"

/* Mocks */

MOCK_ABORT_PTR(uri_refget, rpki_uri, struct rpki_uri *uri)
MOCK_VOID(uri_refput, struct rpki_uri *uri)
__MOCK_ABORT(uri_get_local, char const *, NULL, struct rpki_uri *uri)
MOCK(uri_val_get_printable, char const *, "uri", struct rpki_uri *uri)
MOCK_ABORT_VOID(fnstack_push_uri, struct rpki_uri *uri)
MOCK_ABORT_VOID(fnstack_pop, void)

/* Mocks end */

#define END 0xFFFF

static int
__sort_deltas(struct notification_deltas *deltas, unsigned int max_serial,
   char const *max_serial_str)
{
	struct update_notification notif;
	int error;

	notif.deltas = *deltas;
	notif.session.serial.num = BN_create();
	if (!BN_set_word(notif.session.serial.num, max_serial))
		enomem_panic();
	notif.session.serial.str = (unsigned char *) max_serial_str;

	error = sort_deltas(&notif);

	BN_free(notif.session.serial.num);
	return error;
}

static void
add_serials(struct notification_deltas *deltas, ...)
{
	struct notification_delta delta = { 0 };
	unsigned long cursor;
	va_list vl;

	va_start(vl, deltas);
	while ((cursor = va_arg(vl, unsigned long)) != END) {
		delta.serial.num = BN_create();
		if (!BN_set_word(delta.serial.num, cursor))
			enomem_panic();
		notification_deltas_add(deltas, &delta);
	}
	va_end(vl);
}

static void
validate_serials(struct notification_deltas *deltas, ...)
{
	BN_ULONG actual;
	unsigned long expected;
	unsigned int i;
	va_list vl;

	va_start(vl, deltas);

	i = 0;
	while ((expected = va_arg(vl, unsigned long)) != END) {
		actual = BN_get_word(deltas->array[i].serial.num);
		ck_assert_uint_eq(expected, actual);
		i++;
	}

	va_end(vl);
}

START_TEST(test_sort_deltas)
{
	struct notification_deltas deltas;

	notification_deltas_init(&deltas);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 0, "0"));
	ck_assert_int_eq(0, __sort_deltas(&deltas, 1, "1"));
	ck_assert_int_eq(0, __sort_deltas(&deltas, 2, "2"));

	add_serials(&deltas, 0, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 0, "0"));
	validate_serials(&deltas, 0, END);

	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 2, "2"));
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 1, "1"));

	add_serials(&deltas, 1, 2, 3, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 3, "3"));
	validate_serials(&deltas, 0, 1, 2, 3, END);

	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 4, "4"));
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 2, "2"));

	notification_deltas_cleanup(&deltas, notification_delta_destroy);
	notification_deltas_init(&deltas);

	add_serials(&deltas, 3, 0, 1, 2, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 3, "3"));
	validate_serials(&deltas, 0, 1, 2, 3, END);

	notification_deltas_cleanup(&deltas, notification_delta_destroy);
	notification_deltas_init(&deltas);

	add_serials(&deltas, 4, 3, 2, 1, 0, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 4, "4"));
	validate_serials(&deltas, 0, 1, 2, 3, 4, END);

	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 5, "5"));
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 3, "3"));

	notification_deltas_cleanup(&deltas, notification_delta_destroy);
}
END_TEST

Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *validate;

	validate = tcase_create("Validate");
	tcase_add_test(validate, test_sort_deltas);

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
