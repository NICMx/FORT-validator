#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "alloc.c"
#include "base64.c"
#include "cachetmp.c"
#include "common.c"
#include "file.c"
#include "hash.c"
#include "json_util.c"
#include "mock.c"
#include "relax_ng.c"
#include "rrdp.c"
#include "types/map.c"
#include "types/path.c"
#include "types/url.c"

/* Mocks */

MOCK_ABORT_INT(http_download, char const *url, char const *path, curl_off_t ims,
    bool *changed)

/* Mocks end */

static void
ck_rrdp_session(char const *session, char const *serial,
    struct rrdp_session *actual)
{
	BIGNUM *bn;

	ck_assert_str_eq(session, actual->session_id);
	ck_assert_str_eq(serial, actual->serial.str);

	bn = BN_new();
	ck_assert_ptr_ne(NULL, bn);
	ck_assert_int_eq(strlen(serial), BN_dec2bn(&bn, serial));
	ck_assert_int_eq(0, BN_cmp(bn, actual->serial.num));
	BN_free(bn);
}

static struct rrdp_state *
create_rrdp_state(char const *session, char const *serial, ...)
{
	struct rrdp_state *state;
	struct rrdp_hash *hash;
	int dh_byte;
	va_list args;

	state = pmalloc(sizeof(struct rrdp_state));

	state->session.session_id = pstrdup(session);
	state->session.serial.str = pstrdup(serial);
	state->session.serial.num = NULL; /* Not needed for now. */
	state->files = NULL;
	STAILQ_INIT(&state->delta_hashes);

	va_start(args, serial);
	while ((dh_byte = va_arg(args, int)) != 0) {
		hash = pmalloc(sizeof(struct rrdp_hash));
		memset(hash->bytes, dh_byte, sizeof(hash->bytes));
		STAILQ_INSERT_TAIL(&state->delta_hashes, hash, hook);
	}
	va_end(args);

	return state;
}

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
	size_t sha_len;
	unsigned int i;

	hex = "01";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *)hex, &sha, &sha_len));
	ck_assert_ptr_eq(NULL, sha);

	hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	sha_len = 0;
	ck_assert_int_eq(0, hexstr2sha256((xmlChar *)hex, &sha, &sha_len));
	ck_assert_ptr_ne(NULL, sha);
	for (i = 0; i < 32; i++)
		ck_assert_uint_eq(i, sha[i]);
	ck_assert_uint_eq(32, sha_len);
	free(sha);
	sha = NULL;

	/* Unwanted prefix */
	hex = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *)hex, &sha, &sha_len));
	ck_assert_ptr_eq(NULL, sha);

	/* Padding left */
	hex = " 00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *)hex, &sha, &sha_len));
	ck_assert_ptr_eq(NULL, sha);

	/* Padding right */
	hex = "00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f ";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *)hex, &sha, &sha_len));
	ck_assert_ptr_eq(NULL, sha);

	/* Illegal hex character 'g' */
	hex = "0001020g0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *)hex, &sha, &sha_len));
	ck_assert_ptr_eq(NULL, sha);

	/* Slightly too short */
	hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *)hex, &sha, &sha_len));
	ck_assert_ptr_eq(NULL, sha);

	/* Slightly too long */
	hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2";
	ck_assert_int_eq(EINVAL, hexstr2sha256((xmlChar *)hex, &sha, &sha_len));
	ck_assert_ptr_eq(NULL, sha);
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
	add_serials(&deltas, 2, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 2, "2"));
	validate_serials(&deltas, 2, END);

	/* Delta serial doesn't match session serial */
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 4, "4"));
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 3, "3"));
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 1, "1"));
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 0, "0"));

	/* More than 1 delta, already sorted */
	add_serials(&deltas, 3, 4, 5, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 5, "5"));
	validate_serials(&deltas, 2, 3, 4, 5, END);

	/* More than 1 delta, they don't match session serial */
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 6, "6"));
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 4, "4"));

	notification_deltas_cleanup(&deltas, notification_delta_cleanup);
	notification_deltas_init(&deltas);

	/* More than 1 delta, not already sorted but otherwise functional */
	add_serials(&deltas, 3, 0, 1, 2, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 3, "3"));
	validate_serials(&deltas, 0, 1, 2, 3, END);

	notification_deltas_cleanup(&deltas, notification_delta_cleanup);
	notification_deltas_init(&deltas);

	/* Same, but order completely backwards */
	add_serials(&deltas, 4, 3, 2, 1, 0, END);
	ck_assert_int_eq(0, __sort_deltas(&deltas, 4, "4"));
	validate_serials(&deltas, 0, 1, 2, 3, 4, END);

	/* Same, but deltas don't match session serial */
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 5, "5"));
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 3, "3"));

	notification_deltas_cleanup(&deltas, notification_delta_cleanup);
	notification_deltas_init(&deltas);

	/* More than 1 delta, 1 serial missing */
	add_serials(&deltas, 1, 2, 4, END);
	ck_assert_int_eq(-EINVAL, __sort_deltas(&deltas, 4, "4"));
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

static void
init_serial(struct rrdp_serial *serial, unsigned long num)
{
	char *tmp;

	serial->num = BN_create();
	ck_assert_int_eq(1, BN_add_word(serial->num, num));

	tmp = BN_bn2dec(serial->num);
	ck_assert_ptr_ne(NULL, tmp);
	serial->str = pstrdup(tmp);
	OPENSSL_free(tmp);
}

static void
init_rrdp_session(struct rrdp_session *session, unsigned long serial)
{
	session->session_id = pstrdup("session");
	init_serial(&session->serial, serial);
}

static void
init_rrdp_state(struct rrdp_state **result,
    unsigned long serial, ...)
{
	struct rrdp_state *notif;
	va_list args;
	int hash_byte;
	struct rrdp_hash *hash;
	size_t i;

	notif = pmalloc(sizeof(struct rrdp_state));
	*result = notif;

	init_rrdp_session(&notif->session, serial);
	STAILQ_INIT(&notif->delta_hashes);

	va_start(args, serial);
	while ((hash_byte = va_arg(args, int)) >= 0) {
		hash = pmalloc(sizeof(struct rrdp_hash));
		for (i = 0; i < RRDP_HASH_LEN; i++)
			hash->bytes[i] = hash_byte;
		STAILQ_INSERT_TAIL(&notif->delta_hashes, hash, hook);
	}
	va_end(args);
}

static void
init_regular_notif(struct update_notification *notif, unsigned long serial, ...)
{
	va_list args;
	int hash_byte;
	struct notification_delta delta;
	size_t i;

	memset(notif, 0, sizeof(*notif));
	init_rrdp_session(&notif->session, serial);
	notification_deltas_init(&notif->deltas);

	va_start(args, serial);
	while ((hash_byte = va_arg(args, int)) >= 0) {
		init_serial(&delta.serial, serial--);
		delta.meta.uri = NULL; /* Not needed for now */
		delta.meta.hash = pmalloc(RRDP_HASH_LEN);
		for (i = 0; i < RRDP_HASH_LEN; i++)
			delta.meta.hash[i] = hash_byte;
		delta.meta.hash_len = RRDP_HASH_LEN;
		notification_deltas_add(&notif->deltas, &delta);
	}
	va_end(args);
}

static void
validate_rrdp_state(struct rrdp_state *state, unsigned long __serial, ...)
{
	struct rrdp_serial serial;
	va_list args;
	int hash_byte;
	struct rrdp_hash *hash;
	size_t i;

	ck_assert_str_eq("session", state->session.session_id);
	init_serial(&serial, __serial);
	ck_assert_str_eq(serial.str, state->session.serial.str);
	ck_assert_int_eq(0, BN_cmp(serial.num, state->session.serial.num));
	serial_cleanup(&serial);

	hash = STAILQ_FIRST(&state->delta_hashes);

	va_start(args, __serial);
	while ((hash_byte = va_arg(args, int)) >= 0) {
		ck_assert_ptr_ne(NULL, hash);
		for (i = 0; i < RRDP_HASH_LEN; i++)
			ck_assert_int_eq(hash_byte, hash->bytes[i]);
		hash = STAILQ_NEXT(hash, hook);
	}
	va_end(args);

	ck_assert_ptr_eq(NULL, hash);

	rrdp_state_free(state);
}

START_TEST(test_update_notif)
{
	struct rrdp_state *old;
	struct update_notification new;

	/* No changes */
	init_rrdp_state(&old, 5555, 1, 2, 3, -1);
	init_regular_notif(&new, 5555, 1, 2, 3, -1);
	ck_assert_int_eq(0, update_notif(old, &new));
	validate_rrdp_state(old, 5555, 1, 2, 3, -1);

	/* Add a few serials */
	init_rrdp_state(&old, 5555, 1, 2, 3, -1);
	init_regular_notif(&new, 5557, 3, 4, 5, -1);
	ck_assert_int_eq(0, update_notif(old, &new));
	validate_rrdp_state(old, 5557, 1, 2, 3, 4, 5, -1);

	/* Add serials, delta threshold exceeded */
	init_rrdp_state(&old, 5555, 1, 2, 3, -1);
	init_regular_notif(&new, 5558, 3, 4, 5, 6, -1);
	ck_assert_int_eq(0, update_notif(old, &new));
	validate_rrdp_state(old, 5558, 2, 3, 4, 5, 6, -1);

	/* All new serials, but no hashes skipped */
	init_rrdp_state(&old, 5555, 1, 2, 3, -1);
	init_regular_notif(&new, 5557, 4, 5, -1);
	ck_assert_int_eq(0, update_notif(old, &new));
	validate_rrdp_state(old, 5557, 1, 2, 3, 4, 5, -1);

	/* 2 previous tests combined */
	init_rrdp_state(&old, 5555, 1, 2, 3, 4, 5, -1);
	init_regular_notif(&new, 5560, 6, 7, 8, 9, 10, -1);
	ck_assert_int_eq(0, update_notif(old, &new));
	validate_rrdp_state(old, 5560, 6, 7, 8, 9, 10, -1);
}
END_TEST

START_TEST(test_parse_notification_ok)
{
	struct update_notification notif;

	ck_assert_int_eq(0, relax_ng_init());
	ck_assert_int_eq(0, parse_notification("https://host/notification.xml",
	    "resources/rrdp/notif-ok.xml", &notif));

	ck_assert_str_eq("9df4b597-af9e-4dca-bdda-719cce2c4e28",
	    (char const *)notif.session.session_id);
	ck_assert_str_eq("3", (char const *)notif.session.serial.str);

	ck_assert_str_eq("https://host/9d-8/3/snapshot.xml", notif.snapshot.uri);
	ck_assert_uint_eq(32, notif.snapshot.hash_len);
	validate_aaaa_hash(notif.snapshot.hash);

	ck_assert_uint_eq(2, notif.deltas.len);

	ck_assert_str_eq("2", (char const *)notif.deltas.array[0].serial.str);
	ck_assert_str_eq("https://host/9d-8/2/delta.xml",
	    notif.deltas.array[0].meta.uri);
	ck_assert_uint_eq(32, notif.deltas.array[0].meta.hash_len);
	validate_01234_hash(notif.deltas.array[0].meta.hash);

	ck_assert_str_eq("3", (char const *)notif.deltas.array[1].serial.str);
	ck_assert_str_eq("https://host/9d-8/3/delta.xml",
	    notif.deltas.array[1].meta.uri);
	ck_assert_uint_eq(32, notif.deltas.array[1].meta.hash_len);
	validate_01234_hash(notif.deltas.array[0].meta.hash);

	update_notification_cleanup(&notif);
	relax_ng_cleanup();
}
END_TEST

START_TEST(test_parse_notification_0deltas)
{
	struct update_notification notif;

	ck_assert_int_eq(0, relax_ng_init());
	ck_assert_int_eq(0, parse_notification("https://host/notification.xml",
	    "resources/rrdp/notif-0deltas.xml", &notif));

	ck_assert_str_eq("9df4b597-af9e-4dca-bdda-719cce2c4e28",
	    (char const *)notif.session.session_id);
	ck_assert_str_eq("3", (char const *)notif.session.serial.str);

	ck_assert_str_eq("https://host/9d-8/3/snapshot.xml", notif.snapshot.uri);
	ck_assert_uint_eq(32, notif.snapshot.hash_len);
	validate_01234_hash(notif.snapshot.hash);

	ck_assert_uint_eq(0, notif.deltas.len);

	update_notification_cleanup(&notif);
	relax_ng_cleanup();
}
END_TEST

START_TEST(test_parse_notification_large_serial)
{
	struct update_notification notif;

	ck_assert_int_eq(0, relax_ng_init());
	ck_assert_int_eq(0, parse_notification("https://host/notification.xml",
	    "resources/rrdp/notif-large-serial.xml", &notif));

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

	ck_assert_str_eq("https://host/9d-8/3/snapshot.xml", notif.snapshot.uri);
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
	struct update_notification notif;

	ck_assert_int_eq(0, relax_ng_init());
	ck_assert_int_eq(-EINVAL,
	    parse_notification("https://host/notification.xml", file, &notif));

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
	/* XXX not rejected. */
	/* test_parse_notification_error("resources/rrdp/notif-bad-uri-1.xml"); */
	/* test_parse_notification_error("resources/rrdp/notif-bad-uri-2.xml"); */
	/*
	 * FIXME not rejected.
	 * Although this might be intended. If curl and rsync can make sense out
	 * of the space (perhaps by automatically converting it), there would
	 * perhaps be no real reason to complain here.
	 * Needs more research.
	 */
	/* test_parse_notification_error("resources/rrdp/notif-bad-uri-3.xml"); */
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
	struct rrdp_session session;
	struct rrdp_state rpp = { 0 };

	ck_assert_int_eq(0, relax_ng_init());

	session.session_id = "9df4b597-af9e-4dca-bdda-719cce2c4e28";
	session.serial.str = "2";
	session.serial.num = BN_two();

	ck_assert_int_eq(-EINVAL, parse_snapshot(&session,
	    "resources/rrdp/snapshot-bad-publish.xml", &rpp));

	BN_free(session.serial.num);

	relax_ng_cleanup();
}
END_TEST

START_TEST(test_2s_simple)
{
	struct rrdp_state *state;
	json_t *json, *jdeltas;
	char const *str;

	state = create_rrdp_state("session", "1234", 0);

	json = rrdp_state2json(state);
	ck_assert_ptr_ne(NULL, json);

	rrdp_state_free(state);
	state = NULL;

	ck_assert_int_eq(0, json_get_str(json, TAGNAME_SESSION, &str));
	ck_assert_str_eq("session", str);
	ck_assert_int_eq(0, json_get_str(json, TAGNAME_SERIAL, &str));
	ck_assert_str_eq("1234", str);
	ck_assert_int_eq(ENOENT, json_get_array(json, TAGNAME_DELTAS, &jdeltas));

	ck_assert_int_eq(0, rrdp_json2state(json, &state));
	ck_rrdp_session("session", "1234", &state->session);
	ck_assert_uint_eq(true, STAILQ_EMPTY(&state->delta_hashes));

	json_decref(json);
	rrdp_state_free(state);
}
END_TEST

static void
ck_hash(struct rrdp_hash *hash, unsigned char chara)
{
	size_t i;
	for (i = 0; i < sizeof(hash->bytes); i++)
		ck_assert_uint_eq(chara, hash->bytes[i]);
}

START_TEST(test_2s_more)
{
	struct rrdp_state *state;
	struct rrdp_hash *hash;
	json_t *json, *jdeltas;
	char const *str;

	state = create_rrdp_state("session",
	    "123456789012345678901234567890123456789012",
	    0xAA, 0xBB, 0xCD, 0);

	json = rrdp_state2json(state);
	ck_assert_ptr_ne(NULL, json);

	rrdp_state_free(state);
	state = NULL;

	ck_assert_int_eq(0, json_get_str(json, TAGNAME_SESSION, &str));
	ck_assert_str_eq("session", str);
	ck_assert_int_eq(0, json_get_str(json, TAGNAME_SERIAL, &str));
	ck_assert_str_eq("123456789012345678901234567890123456789012", str);
	ck_assert_int_eq(0, json_get_array(json, TAGNAME_DELTAS, &jdeltas));
	ck_assert_uint_eq(3, json_array_size(jdeltas));
	ck_assert_str_eq("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	    json_string_value(json_array_get(jdeltas, 0)));
	ck_assert_str_eq("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	    json_string_value(json_array_get(jdeltas, 1)));
	ck_assert_str_eq("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
	    json_string_value(json_array_get(jdeltas, 2)));

	ck_assert_int_eq(0, rrdp_json2state(json, &state));
	ck_rrdp_session("session", "123456789012345678901234567890123456789012", &state->session);
	hash = STAILQ_FIRST(&state->delta_hashes);
	ck_assert_ptr_ne(NULL, hash);
	ck_hash(hash, 0xAA);
	hash = STAILQ_NEXT(hash, hook);
	ck_assert_ptr_ne(NULL, hash);
	ck_hash(hash, 0xBB);
	hash = STAILQ_NEXT(hash, hook);
	ck_assert_ptr_ne(NULL, hash);
	ck_hash(hash, 0xCD);
	hash = STAILQ_NEXT(hash, hook);
	ck_assert_ptr_eq(NULL, hash);

	json_decref(json);
	rrdp_state_free(state);
}
END_TEST

void
ck_json2state(int expected, char const *json_str)
{
	json_t *json;
	json_error_t error;
	struct rrdp_state *state;

	json = json_loads(json_str, 0, &error);
	ck_assert_ptr_ne(NULL, json);

	state = NULL;
	ck_assert_int_eq(expected, rrdp_json2state(json, &state));

	json_decref(json);
	if (state != NULL)
		rrdp_state_free(state);
}

START_TEST(test_2s_errors)
{
	struct rrdp_state state = { 0 };

	ck_assert_ptr_eq(NULL, rrdp_state2json(&state));
	state.session.session_id = "sid";
	ck_assert_ptr_eq(NULL, rrdp_state2json(&state));

	ck_json2state(ENOENT, "{}");
	ck_json2state(0, "{ \"" TAGNAME_SESSION "\":\"sss\", \"" TAGNAME_SERIAL "\":\"123\" }");
	ck_json2state(-EINVAL, "{ \"" TAGNAME_SESSION "\":null, \"" TAGNAME_SERIAL "\":\"123\" }");
	ck_json2state(-EINVAL, "{ \"" TAGNAME_SESSION "\":\"sss\", \"" TAGNAME_SERIAL "\":null }");
	ck_json2state(-EINVAL, "{ \"" TAGNAME_SESSION "\":123, \"" TAGNAME_SERIAL "\":\"123\" }");
	ck_json2state(-EINVAL, "{ \"" TAGNAME_SESSION "\":\"sss\", \"" TAGNAME_SERIAL "\":123 }");
	ck_json2state(ENOENT, "{ \"" TAGNAME_SESSION "\":\"sss\" }");
	ck_json2state(ENOENT, "{ \"" TAGNAME_SERIAL "\":\"123\" }");
	ck_json2state(-EINVAL,
	    "{ \"" TAGNAME_SESSION "\":\"sss\","
	      "\"" TAGNAME_SERIAL "\":\"123\","
	      "\"" TAGNAME_DELTAS "\":null }");
	ck_json2state(-EINVAL,
	    "{ \"" TAGNAME_SESSION "\":\"sss\","
	      "\"" TAGNAME_SERIAL "\":\"123\","
	      "\"" TAGNAME_DELTAS "\":\"123\" }");
	ck_json2state(-EINVAL,
	    "{ \"" TAGNAME_SESSION "\":\"sss\","
	      "\"" TAGNAME_SERIAL "\":\"123\","
	      "\"" TAGNAME_DELTAS "\":{} }");
	ck_json2state(0,
	    "{ \"" TAGNAME_SESSION "\":\"sss\","
	      "\"" TAGNAME_SERIAL "\":\"123\","
	      "\"" TAGNAME_DELTAS "\":[] }");
	ck_json2state(-EINVAL,
	    "{ \"" TAGNAME_SESSION "\":\"sss\","
	      "\"" TAGNAME_SERIAL "\":\"123\","
	      "\"" TAGNAME_DELTAS "\":[ 1 ] }");
	ck_json2state(-EINVAL,
	    "{ \"" TAGNAME_SESSION "\":\"sss\","
	      "\"" TAGNAME_SERIAL "\":\"123\","
	      "\"" TAGNAME_DELTAS "\":[ \"111\" ] }");
	ck_json2state(0,
	    "{ \"" TAGNAME_SESSION "\":\"sss\","
	      "\"" TAGNAME_SERIAL "\":\"123\","
	      "\"" TAGNAME_DELTAS "\":[ \"1111111111111111111111111111111111111111111111111111111111111111\" ] }");
}
END_TEST

static Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *misc, *parse, *cf;

	misc = tcase_create("misc");
	tcase_add_test(misc, test_xmlChar_NULL_assumption);
	tcase_add_test(misc, test_hexstr2sha256);
	tcase_add_test(misc, test_sort_deltas);
	tcase_add_test(misc, test_update_notif);

	parse = tcase_create("parse");
	tcase_add_test(parse, test_parse_notification_ok);
	tcase_add_test(parse, test_parse_notification_0deltas);
	tcase_add_test(parse, test_parse_notification_large_serial);
	tcase_add_test(parse, test_parse_notification_bad_xmlns);
	tcase_add_test(parse, test_parse_notification_bad_session_id);
	tcase_add_test(parse, test_parse_notification_bad_serial);
	tcase_add_test(parse, test_parse_notification_bad_hash);
	tcase_add_test(parse, test_parse_notification_bad_uri);
	tcase_add_test(parse, test_parse_snapshot_bad_publish);

	cf = tcase_create("cachefile");
	tcase_add_test(parse, test_2s_simple);
	tcase_add_test(parse, test_2s_more);
	tcase_add_test(parse, test_2s_errors);

	suite = suite_create("RRDP");
	suite_add_tcase(suite, misc);
	suite_add_tcase(suite, parse);
	suite_add_tcase(suite, cf);

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
