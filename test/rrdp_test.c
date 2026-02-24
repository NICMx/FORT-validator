#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "alloc.c"
#include "asn1/asn1c/INTEGER.c"
#include "asn1/asn1c/asn_codecs_prim.c"
#include "asn1/asn1c/asn_internal.c"
#include "asn1/asn1c/ber_decoder.c"
#include "asn1/asn1c/ber_tlv_length.c"
#include "asn1/asn1c/ber_tlv_tag.c"
#include "asn1/asn1c/der_encoder.c"
#include "base64.c"
#include "cachefile.c"
#include "common.c"
#include "file.c"
#include "json_util.c"
#include "hash.c"
#include "mock.c"
#include "relax_ng.c"
#include "rrdp.c"
#include "types/uri.c"
#include "types/map.c"
#include "types/path.c"
#include "types/str.c"

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

#define END 0xFFFF

static int
__sort_deltas(struct notification_deltas *deltas, unsigned int max_serial,
   char *max_serial_str)
{
	struct update_notification notif;
	int error;

	notif.deltas = *deltas;
	notif.session.serial.num = BN_create();
	if (!BN_set_word(notif.session.serial.num, max_serial))
		ck_abort_msg("BN_set_word() returned zero.");
	notif.session.serial.str = max_serial_str;

	error = sort_deltas(&notif);

	BN_free(notif.session.serial.num);
	return error;
}

/* Not really designed to be used with args > END (because of @str). */
static void
add_serials(struct notification_deltas *deltas, ...)
{
	struct notification_delta delta = { 0 };
	int cursor;
	char str[6];
	int written;
	va_list vl;

	va_start(vl, deltas);
	while ((cursor = va_arg(vl, int)) != END) {
		delta.serial.num = BN_create();
		if (!BN_set_word(delta.serial.num, cursor))
			ck_abort_msg("BN_set_word() returned zero.");

		written = snprintf(str, sizeof(str), "%d", cursor) < sizeof(str);
		ck_assert(1 <= written && written <= sizeof(str));
		delta.serial.str = pstrdup(str);

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

	/* No deltas */
	notification_deltas_init(&deltas);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 0, "0"));
	ck_assert_int_eq(0, __sort_deltas(&deltas, 1, "1"));
	ck_assert_int_eq(0, __sort_deltas(&deltas, 2, "2"));

	/* 1 delta */
	add_serials(&deltas, 5, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 5, "5"));
	validate_serials(&deltas, 5, END);

	/* Delta serial doesn't match session serial */
	ck_assert_int_eq(EINVAL, __sort_deltas(&deltas, 7, "7"));
	ck_assert_int_eq(EINVAL, __sort_deltas(&deltas, 6, "6"));
	ck_assert_int_eq(EINVAL, __sort_deltas(&deltas, 4, "4"));
	ck_assert_int_eq(EINVAL, __sort_deltas(&deltas, 3, "3"));

	/* More than 1 delta, already sorted */
	add_serials(&deltas, 4, 3, 2, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 5, "5"));
	validate_serials(&deltas, 5, 4, 3, 2, END);

	/* More than 1 delta, they don't match session serial */
	ck_assert_int_eq(EINVAL, __sort_deltas(&deltas, 6, "6"));
	ck_assert_int_eq(EINVAL, __sort_deltas(&deltas, 4, "4"));

	notification_deltas_cleanup(&deltas, notification_delta_cleanup);
	notification_deltas_init(&deltas);

	/* More than 1 delta, not already sorted but otherwise functional */
	add_serials(&deltas, 3, 0, 1, 2, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 3, "3"));
	validate_serials(&deltas, 3, 2, 1, 0, END);

	notification_deltas_cleanup(&deltas, notification_delta_cleanup);
	notification_deltas_init(&deltas);

	/* Same, but order completely backwards */
	add_serials(&deltas, 0, 1, 2, 3, 4, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 4, "4"));
	validate_serials(&deltas, 4, 3, 2, 1, 0, END);

	/* Same, but deltas don't match session serial */
	ck_assert_int_eq(EINVAL, __sort_deltas(&deltas, 5, "5"));
	ck_assert_int_eq(EINVAL, __sort_deltas(&deltas, 3, "3"));

	notification_deltas_cleanup(&deltas, notification_delta_cleanup);
	notification_deltas_init(&deltas);

	/* More than 1 delta, 1 serial missing */
	add_serials(&deltas, 4, 2, 1, END);
	ck_assert_int_eq(EINVAL, __sort_deltas(&deltas, 4, "4"));
}
END_TEST

static void
validate_aaaa_hash(struct rrdp_hash *hash)
{
	size_t i;
	for (i = 0; i < RRDP_HASH_LEN; i++)
		ck_assert_uint_eq(0xaa, hash->bytes[i]);
	ck_assert_int_eq(true, hash->set);
}

static void
validate_01234_hash(struct rrdp_hash *hash)
{
	static unsigned char expected_hash[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xcd,
		0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xab,
		0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xab, 0xcd
	};

	size_t i;
	for (i = 0; i < RRDP_HASH_LEN; i++)
		ck_assert_uint_eq(expected_hash[i], hash->bytes[i]);
	ck_assert_int_eq(true, hash->set);
}

START_TEST(test_parse_notification_ok)
{
	struct update_notification notif;
	struct uri nurl;

	ck_assert_int_eq(0, relax_ng_init());
	ck_assert_ptr_eq(NULL, uri_init(&nurl, "https://host/notification.xml"));
	ck_assert_int_eq(0, parse_notification(&nurl,
	    "resources/rrdp/notif-ok.xml", &notif));
	uri_cleanup(&nurl);

	ck_assert_str_eq("9df4b597-af9e-4dca-bdda-719cce2c4e28",
	    notif.session.session_id);
	ck_assert_str_eq("3", notif.session.serial.str);

	ck_assert_uri("https://host/9d-8/3/snapshot.xml", &notif.snapshot.uri);
	validate_aaaa_hash(&notif.snapshot.hash);

	ck_assert_uint_eq(2, notif.deltas.len);

	ck_assert_str_eq("3", notif.deltas.array[0].serial.str);
	ck_assert_uri("https://host/9d-8/3/delta.xml",
	    &notif.deltas.array[0].meta.uri);
	validate_01234_hash(&notif.deltas.array[0].meta.hash);

	ck_assert_str_eq("2", notif.deltas.array[1].serial.str);
	ck_assert_uri("https://host/9d-8/2/delta.xml",
	    &notif.deltas.array[1].meta.uri);
	validate_01234_hash(&notif.deltas.array[1].meta.hash);

	notification_cleanup(&notif);
	relax_ng_cleanup();
}
END_TEST

START_TEST(test_parse_notification_0deltas)
{
	struct update_notification notif;
	struct uri nurl;

	ck_assert_int_eq(0, relax_ng_init());
	ck_assert_ptr_eq(NULL, uri_init(&nurl, "https://host/notification.xml"));
	ck_assert_int_eq(0, parse_notification(&nurl,
	    "resources/rrdp/notif-0deltas.xml", &notif));
	uri_cleanup(&nurl);

	ck_assert_str_eq("9df4b597-af9e-4dca-bdda-719cce2c4e28",
	    notif.session.session_id);
	ck_assert_str_eq("3", notif.session.serial.str);

	ck_assert_uri("https://host/9d-8/3/snapshot.xml", &notif.snapshot.uri);
	validate_01234_hash(&notif.snapshot.hash);

	ck_assert_uint_eq(0, notif.deltas.len);

	notification_cleanup(&notif);
	relax_ng_cleanup();
}
END_TEST

START_TEST(test_parse_notification_large_serial)
{
	struct update_notification notif;
	struct uri nurl;

	ck_assert_int_eq(0, relax_ng_init());
	ck_assert_ptr_eq(NULL, uri_init(&nurl, "https://host/notification.xml"));
	ck_assert_int_eq(0, parse_notification(&nurl,
	    "resources/rrdp/notif-large-serial.xml", &notif));
	uri_cleanup(&nurl);

	ck_assert_str_eq("9df4b597-af9e-4dca-bdda-719cce2c4e28",
	    (char const *)notif.session.session_id);
	/*
	 * This seems to be the largest positive integer libxml2 supports,
	 * at least by default. It's significantly larger than 2^64.
	 * It's not as many digits as I was expecting though.
	 * Maybe research if it's possible to increase it further.
	 */
	ck_assert_str_eq("999999999999999999999999",
	    (char const *)notif.session.serial.str);

	ck_assert_uri("https://host/9d-8/3/snapshot.xml", &notif.snapshot.uri);
	validate_01234_hash(&notif.snapshot.hash);

	ck_assert_uint_eq(0, notif.deltas.len);

	notification_cleanup(&notif);
	relax_ng_cleanup();
}
END_TEST

static void
test_parse_notification_error(char *file)
{
	struct update_notification notif;
	struct uri nurl;

	ck_assert_int_eq(0, relax_ng_init());
	ck_assert_ptr_eq(NULL, uri_init(&nurl, "https://host/notification.xml"));
	ck_assert_int_eq(EINVAL, parse_notification(&nurl, file, &notif));
	uri_cleanup(&nurl);

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
	test_parse_notification_error("resources/rrdp/notif-bad-uri-3.xml");
	test_parse_notification_error("resources/rrdp/notif-bad-uri-4.xml");
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
	struct rrdp_id id;
	struct rrdp_session session = { 0 };
	struct cache_sequence seq = { 0 };

	ck_assert_int_eq(0, relax_ng_init());

	id.session_id = "9df4b597-af9e-4dca-bdda-719cce2c4e28";
	id.serial.str = "2";
	id.serial.num = BN_two();

	TAILQ_INIT(&session.steps);

	cseq_init(&seq, "a", 1, false);

	ck_assert_int_eq(EINVAL, parse_snapshot(&id,
	    "resources/rrdp/snapshot-bad-publish.xml",
	    &session, &seq));

	BN_free(id.serial.num);

	relax_ng_cleanup();
}
END_TEST

/* Converts @src into JSON forth and back. Checks the result equals @src. */
static void
ck_json(struct rrdp_ctx const *src)
{
	struct rrdp_ctx *dst;
	json_t *json;

	json = rrdp_ctx2json(src);
	json_dumpf(json, stdout, JSON_INDENT(2));
	printf("\n");
	ck_assert_ptr_ne(NULL, json);
	ck_assert_int_eq(0, rrdp_json2ctx(json, src->seq.pfx.str, &dst));
	json_decref(json);

	/* FIXME (test) not checking sessions */
	if (TAILQ_EMPTY(&src->sessions))
		ck_assert_int_eq(true, TAILQ_EMPTY(&dst->sessions));
	ck_assert_str_eq(src->seq.pfx.str, dst->seq.pfx.str);
	ck_assert_int_eq(src->seq.next_id, dst->seq.next_id);

	rrdpctx_free(dst);
}

struct cache_file *
_cachefile_create(char const *uri, char *path, int hashchr)
{
	struct uri _uri;
	unsigned char hash[RRDP_HASH_LEN];

	__URI_INIT(&_uri, uri);
	memset(hash, hashchr, RRDP_HASH_LEN);

	return cachefile_create(&_uri, path, strrchr(path, '/') + 1, hash);
}

static void
step_add_fileref(struct rrdp_step *step, struct cache_file *file)
{
	struct cache_file_ref *fileref;
	char const *urlstr;
	size_t urlen;

	fileref = fileref_create(file);
	urlstr = uri_str(&fileref->file->map.url);
	urlen = uri_len(&fileref->file->map.url);
	HASH_ADD_KEYPTR(hh, step->files, urlstr, urlen, fileref);
}

static void
add_step(struct rrdp_session *session, char const *serial, int hashchr, ...)
{
	struct rrdp_step *step;
	va_list ap;
	struct cache_file *file;

	step = pzalloc(sizeof(struct rrdp_step));
	TAILQ_INSERT_TAIL(&session->steps, step, lh);

	ck_assert_int_eq(0, str2serial(serial, &step->serial));

	va_start(ap, hashchr);
	while ((file = va_arg(ap, struct cache_file *)) != NULL)
		step_add_fileref(step, file);
	va_end(ap);

	memset(step->delta_hash.bytes, hashchr, RRDP_HASH_LEN);
	step->delta_hash.set = true;
}

START_TEST(test_json)
{
	/* TODO (fine) no cleanup */

	struct rrdp_ctx ctx;
	struct rrdp_session se1, se2;
	struct cache_file *f1, *f2, *f3, *f4;

	f1 = _cachefile_create("https://n/a.cer", "https/22/0", 0x0a);
	f2 = _cachefile_create("https://n/b.cer", "https/22/1", 0x0b);
	f3 = _cachefile_create("https://n/c.cer", "https/22/2", 0x0c);
	f4 = _cachefile_create("https://n/d.cer", "https/22/3", 0x0d);

	TAILQ_INIT(&ctx.sessions);

	TAILQ_INSERT_TAIL(&ctx.sessions, &se1, lh);
	se1.id = "session1";
	TAILQ_INIT(&se1.steps);
	add_step(&se1, "3", 0x03, f1, f4, NULL);
	add_step(&se1, "2", 0x02, f2, f3, f4, NULL);
	add_step(&se1, "1", 0x01, f1, f2, f3, NULL);
	se1.fresh = false;
	ck_assert_int_eq(0, pthread_mutex_init(&se1.lock, NULL));
	se1.fbs.ht = NULL;

	TAILQ_INSERT_TAIL(&ctx.sessions, &se2, lh);
	se2.id = "session2";
	TAILQ_INIT(&se2.steps);
	add_step(&se2, "6", 0x06, f1, f4, NULL);
	add_step(&se2, "5", 0x05, f2, f3, f4, NULL);
	add_step(&se2, "4", 0x04, f1, f2, f3, NULL);
	se2.fresh = true;
	ck_assert_int_eq(0, pthread_mutex_init(&se2.lock, NULL));
	se2.fbs.ht = NULL;

	cseq_init(&ctx.seq, "http/22", 4, false);

	ck_json(&ctx);
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *misc, *xml, *json;

	misc = tcase_create("misc");
	tcase_add_test(misc, test_xmlChar_NULL_assumption);
	tcase_add_test(misc, test_sort_deltas);

	xml = tcase_create("xml");
	tcase_add_test(xml, test_parse_notification_ok);
	tcase_add_test(xml, test_parse_notification_0deltas);
	tcase_add_test(xml, test_parse_notification_large_serial);
	tcase_add_test(xml, test_parse_notification_bad_xmlns);
	tcase_add_test(xml, test_parse_notification_bad_session_id);
	tcase_add_test(xml, test_parse_notification_bad_serial);
	tcase_add_test(xml, test_parse_notification_bad_hash);
	tcase_add_test(xml, test_parse_notification_bad_uri);
	tcase_add_test(xml, test_parse_snapshot_bad_publish);

	json = tcase_create("json");
	tcase_add_test(json, test_json);

	suite = suite_create("RRDP");
	suite_add_tcase(suite, misc);
	suite_add_tcase(suite, xml);
	suite_add_tcase(suite, json);

	return suite;
}

int
main(void)
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
