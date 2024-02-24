#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "alloc.c"
#include "mock.c"
#include "rrdp.c"

/* Mocks */

MOCK_ABORT_INT(__uri_create, struct rpki_uri **result, char const *tal,
    enum uri_type type, bool is_notif, struct rpki_uri *notif, void const *guri,
    size_t guri_len)
__MOCK_ABORT(base64_decode, bool, false, BIO *in, unsigned char *out,
    bool has_nl, size_t out_len, size_t *out_written)
MOCK_ABORT_INT(cache_download, struct rpki_cache *cache, struct rpki_uri *uri,
    bool *changed)
MOCK_ABORT_VOID(file_close, FILE *file)
MOCK_ABORT_INT(file_rm_rf, char const *path)
MOCK_ABORT_INT(file_write, char const *file_name, FILE **result)
MOCK_ABORT_INT(delete_dir_recursive_bottom_up, char const *path)
MOCK_ABORT_INT(mkdir_p, char const *path, bool include_basename)
MOCK_ABORT_VOID(fnstack_pop, void)
MOCK_ABORT_VOID(fnstack_push_uri, struct rpki_uri *uri)
MOCK_ABORT_INT(hash_validate_file, struct rpki_uri *uri,
    unsigned char const *expected, size_t expected_len)
MOCK_ABORT_INT(relax_ng_parse, const char *path, xml_read_cb cb, void *arg)
MOCK_ABORT_PTR(state_retrieve, validation, void)
__MOCK_ABORT(tal_get_file_name, char const *, NULL, struct tal *tal)
__MOCK_ABORT(uri_get_global, char const *, NULL, struct rpki_uri *uri)
__MOCK_ABORT(uri_get_local, char const *, NULL, struct rpki_uri *uri)
__MOCK_ABORT(uri_get_rrdp_workspace, char *, NULL, char const *tal,
    struct rpki_uri *notif)
MOCK_ABORT_PTR(uri_refget, rpki_uri, struct rpki_uri *uri)
MOCK_VOID(uri_refput, struct rpki_uri *uri)
MOCK(uri_val_get_printable, char const *, "uri", struct rpki_uri *uri)
MOCK_ABORT_PTR(validation_cache, rpki_cache, struct validation *state)
MOCK_ABORT_PTR(validation_tal, tal, struct validation *state)

/* Mocks end */

START_TEST(test_hexstr2sha256)
{
	char *hex;
	unsigned char *sha = NULL;
	unsigned int i;

	hex = "01";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *) hex, &sha));
	ck_assert_ptr_eq(NULL, sha);

	hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	ck_assert_int_eq(0, hexstr2sha256((xmlChar *) hex, &sha));
	ck_assert_ptr_ne(NULL, sha);
	for (i = 0; i < 32; i++)
		ck_assert_uint_eq(i, sha[i]);
	free(sha);
	sha = NULL;

	hex = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *) hex, &sha));
	ck_assert_ptr_eq(NULL, sha);

	hex = " 00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *) hex, &sha));
	ck_assert_ptr_eq(NULL, sha);

	hex = "0001020g0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *) hex, &sha));
	ck_assert_ptr_eq(NULL, sha);

	hex = "0001020g0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *) hex, &sha));
	ck_assert_ptr_eq(NULL, sha);

	hex = "0001020g0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *) hex, &sha));
	ck_assert_ptr_eq(NULL, sha);
}
END_TEST

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
		ck_abort_msg("BN_set_word() returned zero.");
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
			ck_abort_msg("BN_set_word() returned zero.");
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

	notification_deltas_cleanup(&deltas, notification_delta_cleanup);
	notification_deltas_init(&deltas);

	add_serials(&deltas, 3, 0, 1, 2, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 3, "3"));
	validate_serials(&deltas, 0, 1, 2, 3, END);

	notification_deltas_cleanup(&deltas, notification_delta_cleanup);
	notification_deltas_init(&deltas);

	add_serials(&deltas, 4, 3, 2, 1, 0, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 4, "4"));
	validate_serials(&deltas, 0, 1, 2, 3, 4, END);

	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 5, "5"));
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 3, "3"));

	notification_deltas_cleanup(&deltas, notification_delta_cleanup);
}
END_TEST

static Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *misc;

	misc = tcase_create("misc");
	tcase_add_test(misc, test_hexstr2sha256);
	tcase_add_test(misc, test_sort_deltas);

	suite = suite_create("RRDP");
	suite_add_tcase(suite, misc);

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
