#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "alloc.c"
#include "common.c"
#include "file.c"
#include "mock.c"
#include "rrdp.c"
#include "crypto/base64.c"
#include "crypto/hash.c"
#include "data_structure/path_builder.c"
#include "types/uri.c"
#include "xml/relax_ng.c"

/* Mocks */

MOCK_ABORT_INT(cache_download, struct rpki_cache *cache, struct rpki_uri *uri,
    bool *changed)
MOCK_ABORT_VOID(fnstack_pop, void)
MOCK_ABORT_VOID(fnstack_push_uri, struct rpki_uri *uri)
MOCK_ABORT_PTR(validation_cache, rpki_cache, struct validation *state)

MOCK(state_retrieve, struct validation *, NULL, void)
MOCK(validation_tal, struct tal *, NULL, struct validation *state)
MOCK(tal_get_file_name, char const *, "", struct tal *tal)

/* Mocks end */

START_TEST(test_xmlChar_NULL_assumption)
{
	xmlChar *xmlstr;

	/*
	 * The RRDP code relies on xmlChar*s being NULL-terminated.
	 * But this isn't guaranteed by any contracts. Still, because of
	 * BAD_CAST, it's very hard to imagine a future in which xmlChar is
	 * typedef'd into a struct with a length or whatever.
	 *
	 * So... instead of complicating RRDP more, I decided to validate the
	 * assumption in this unit test. If they change the implementation and
	 * violate the assumption, this should catch it.
	 *
	 * For added noise, this also incidentally tests other assumptions about
	 * xmlChar*s. They're not important.
	 */

	xmlstr = xmlCharStrdup("Fort");
	ck_assert_ptr_ne(NULL, xmlstr);
	ck_assert_uint_eq('F', xmlstr[0]);
	ck_assert_uint_eq('o', xmlstr[1]);
	ck_assert_uint_eq('r', xmlstr[2]);
	ck_assert_uint_eq('t', xmlstr[3]);
	ck_assert_uint_eq('\0', xmlstr[4]);
	xmlFree(xmlstr);

	xmlstr = xmlCharStrdup("");
	ck_assert_ptr_ne(NULL, xmlstr);
	ck_assert_uint_eq('\0', xmlstr[0]);
	xmlFree(xmlstr);

	xmlstr = xmlCharStrdup("砦");
	ck_assert_ptr_ne(NULL, xmlstr);
	ck_assert_uint_eq(0xe7, xmlstr[0]);
	ck_assert_uint_eq(0xa0, xmlstr[1]);
	ck_assert_uint_eq(0xa6, xmlstr[2]);
	ck_assert_uint_eq('\0', xmlstr[3]);
	xmlFree(xmlstr);

}
END_TEST

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

static void
validate_aaaa_hash(unsigned char *hash)
{
	size_t i;
	for (i = 0; i < 32; i++)
		ck_assert_uint_eq(0xaa, hash[i]);
}

static void
validate_01234_hash(unsigned char *hash)
{
	static unsigned char expected_hash[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xcd,
		0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xab,
		0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xab, 0xcd
	};

	size_t i;
	for (i = 0; i < 32; i++)
		ck_assert_uint_eq(expected_hash[i], hash[i]);
}

START_TEST(test_parse_notification_ok)
{
	struct rpki_uri uri = { 0 };
	struct update_notification notif;

	ck_assert_int_eq(0, relax_ng_init());
	uri.local = "resources/rrdp/notif-ok.xml";
	uri.references = 1;
	ck_assert_int_eq(0, parse_notification(&uri, &notif));

	ck_assert_str_eq("9df4b597-af9e-4dca-bdda-719cce2c4e28", (char const *)notif.session.session_id);
	ck_assert_str_eq("3", (char const *)notif.session.serial.str);

	ck_assert_str_eq("https://host/9d-8/3/snapshot.xml", notif.snapshot.uri->global);
	ck_assert_uint_eq(32, notif.snapshot.hash_len);
	validate_aaaa_hash(notif.snapshot.hash);

	ck_assert_uint_eq(2, notif.deltas.len);

	ck_assert_str_eq("2", (char const *)notif.deltas.array[0].serial.str);
	ck_assert_str_eq("https://host/9d-8/2/delta.xml", notif.deltas.array[0].meta.uri->global);
	ck_assert_uint_eq(32, notif.deltas.array[0].meta.hash_len);
	validate_01234_hash(notif.deltas.array[0].meta.hash);

	ck_assert_str_eq("3", (char const *)notif.deltas.array[1].serial.str);
	ck_assert_str_eq("https://host/9d-8/3/delta.xml", notif.deltas.array[1].meta.uri->global);
	ck_assert_uint_eq(32, notif.deltas.array[1].meta.hash_len);
	validate_01234_hash(notif.deltas.array[0].meta.hash);

	update_notification_cleanup(&notif);
	relax_ng_cleanup();
}
END_TEST

START_TEST(test_parse_notification_0deltas)
{
	struct rpki_uri uri = { 0 };
	struct update_notification notif;

	ck_assert_int_eq(0, relax_ng_init());
	uri.local = "resources/rrdp/notif-0deltas.xml";
	uri.references = 1;
	ck_assert_int_eq(0, parse_notification(&uri, &notif));

	ck_assert_str_eq("9df4b597-af9e-4dca-bdda-719cce2c4e28", (char const *)notif.session.session_id);
	ck_assert_str_eq("3", (char const *)notif.session.serial.str);

	ck_assert_str_eq("https://host/9d-8/3/snapshot.xml", notif.snapshot.uri->global);
	ck_assert_uint_eq(32, notif.snapshot.hash_len);
	validate_01234_hash(notif.snapshot.hash);

	ck_assert_uint_eq(0, notif.deltas.len);

	update_notification_cleanup(&notif);
	relax_ng_cleanup();
}
END_TEST

START_TEST(test_parse_notification_large_serial)
{
	struct rpki_uri uri = { 0 };
	struct update_notification notif;

	ck_assert_int_eq(0, relax_ng_init());
	uri.local = "resources/rrdp/notif-large-serial.xml";
	uri.references = 1;
	ck_assert_int_eq(0, parse_notification(&uri, &notif));

	ck_assert_str_eq("9df4b597-af9e-4dca-bdda-719cce2c4e28", (char const *)notif.session.session_id);
	/*
	 * This seems to be the largest positive integer libxml2 supports,
	 * at least by default. It's significantly larger than 2^64.
	 * It's not as many digits as I was expecting though.
	 * Maybe research if it's possible to increase it further.
	 */
	ck_assert_str_eq("999999999999999999999999", (char const *)notif.session.serial.str);

	ck_assert_str_eq("https://host/9d-8/3/snapshot.xml", notif.snapshot.uri->global);
	ck_assert_uint_eq(32, notif.snapshot.hash_len);
	validate_01234_hash(notif.snapshot.hash);

	ck_assert_uint_eq(0, notif.deltas.len);

	update_notification_cleanup(&notif);
	relax_ng_cleanup();
}
END_TEST

static void
test_parse_notification_error(char *file)
{
	struct rpki_uri uri = { 0 };
	struct update_notification notif;

	ck_assert_int_eq(0, relax_ng_init());
	uri.local = file;
	uri.references = 1;
	ck_assert_int_eq(-EINVAL, parse_notification(&uri, &notif));

	relax_ng_cleanup();
}

START_TEST(test_parse_notification_bad_xmlns)
{
	test_parse_notification_error("resources/rrdp/notif-bad-xmlns.xml");
}
END_TEST

START_TEST(test_parse_notification_bad_session_id)
{
	test_parse_notification_error("resources/rrdp/notif-bad-session-id.xml");
}
END_TEST

START_TEST(test_parse_notification_bad_serial)
{
	test_parse_notification_error("resources/rrdp/notif-bad-serial.xml");
}
END_TEST

START_TEST(test_parse_notification_bad_hash)
{
	test_parse_notification_error("resources/rrdp/notif-bad-hash.xml");
}
END_TEST

START_TEST(test_parse_notification_bad_uri)
{
	test_parse_notification_error("resources/rrdp/notif-bad-uri-1.xml");
	test_parse_notification_error("resources/rrdp/notif-bad-uri-2.xml");
	/*
	 * FIXME not rejected.
	 * Although this might be intended. If curl and rsync can make sense out
	 * of the space (perhaps by automatically converting it), there would
	 * perhaps be no real reason to complain here.
	 * Needs more research.
	 */
	/* test_parse_notification_error("resources/rrdp/notif-bad-uri-3.xml"); */
}
END_TEST

static BIGNUM *
BN_two(void)
{
	BIGNUM *result = BN_new();
	ck_assert_ptr_ne(NULL, result);
	ck_assert_int_eq(1, BN_add_word(result, 2));
	return result;
}

START_TEST(test_parse_snapshot_bad_publish)
{
	struct update_notification notif = { 0 };
	struct rpki_uri notif_uri = { 0 };
	struct rpki_uri snapshot_uri = { 0 };

	ck_assert_int_eq(0, relax_ng_init());

	notif_uri.global = "https://example.com/notification.xml";
	notif_uri.global_len = strlen(notif_uri.global);
	notif_uri.local = "cache/example.com/notification.xml";
	notif_uri.type = UT_HTTPS;
	notif_uri.is_notif = true;
	notif_uri.references = 1;

	snapshot_uri.local = "resources/rrdp/snapshot-bad-publish.xml";
	snapshot_uri.references = 1;

	notif.session.session_id = BAD_CAST "9df4b597-af9e-4dca-bdda-719cce2c4e28";
	notif.session.serial.str = BAD_CAST "2";
	notif.session.serial.num = BN_two();
	notif.snapshot.uri = &snapshot_uri;
	notif.uri = &notif_uri;

	ck_assert_int_eq(-EINVAL, parse_snapshot(&notif));

	BN_free(notif.session.serial.num);

	relax_ng_cleanup();
}
END_TEST

static Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *misc;

	misc = tcase_create("misc");
	tcase_add_test(misc, test_xmlChar_NULL_assumption);
	tcase_add_test(misc, test_hexstr2sha256);
	tcase_add_test(misc, test_sort_deltas);
	tcase_add_test(misc, test_parse_notification_ok);
	tcase_add_test(misc, test_parse_notification_0deltas);
	tcase_add_test(misc, test_parse_notification_large_serial);
	tcase_add_test(misc, test_parse_notification_bad_xmlns);
	tcase_add_test(misc, test_parse_notification_bad_session_id);
	tcase_add_test(misc, test_parse_notification_bad_serial);
	tcase_add_test(misc, test_parse_notification_bad_hash);
	tcase_add_test(misc, test_parse_notification_bad_uri);
	tcase_add_test(misc, test_parse_snapshot_bad_publish);

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
