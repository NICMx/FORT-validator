#include <check.h>

#define XML_BUF_SIZE 128
#define MAX_QUOTE_SIZE 120

#include "alloc.c"
#include "asn1/asn1c/INTEGER.c"
#include "asn1/asn1c/asn_codecs_prim.c"
#include "asn1/asn1c/asn_internal.c"
#include "asn1/asn1c/ber_decoder.c"
#include "asn1/asn1c/ber_tlv_length.c"
#include "asn1/asn1c/ber_tlv_tag.c"
#include "asn1/asn1c/constraints.c"
#include "asn1/asn1c/der_encoder.c"
#include "base64.c"
#include "cachefile.c"
#include "common.c"
#include "file.c"
#include "json_util.c"
#include "hash.c"
#include "mock.c"
#include "rrdp_xml.c"
#include "types/uri.c"
#include "types/map.c"
#include "types/path.c"
#include "types/str.c"

struct xml_test {
	char *xml;
	char const *errmsg; /* If NULL, test is expected to succeed */
	bool drip_feed;
};

static struct xml_test input[32];

MOCK(config_get_http_max_file_size, curl_off_t, 10000, void)
__MOCK_ABORT(config_get_asn1_decode_max_stack, unsigned int, 32, void)

int
http_download(struct uri const *src, curl_write_callback writer,
    void *writer_args, curl_off_t ims, bool *changed)
{
	array_index a, c;
	size_t xmlen;
	size_t result;

	for (a = 0; input[a].xml != NULL; a++) {
		xmlen = strlen(input[a].xml);

		pr_trc("http_download: Feeding %zu bytes", xmlen);

		if (input[a].drip_feed) {
			xmlen = strlen(input[a].xml);
			for (c = 0; c < xmlen; c++) {
				pr_trc("http_download: Feeding 1 byte");

				result = writer(&input[a].xml[c], 1, 1, writer_args);
				if (input[a].errmsg && result == CURL_WRITEFUNC_ERROR)
					return EINVAL; /* Success */
				ck_assert_uint_eq(1, result);
			}

			if (input[a].errmsg)
				ck_abort_msg("Drip feed was supposed to result in eventual failure, but didn't");

		} else {
			result = input[a].errmsg ? CURL_WRITEFUNC_ERROR : xmlen;
			pr_inf("Feeding xml to parser: %s", input[a].xml);
			ck_assert_uint_eq(
			    result,
			    writer(input[a].xml, 1, xmlen, writer_args)
			);

			if (input[a].errmsg == NULL) {
				ck_assert_str_eq("", last_errmsg);
			} else {
				ck_assert_str_eq(input[a].errmsg, last_errmsg);
				last_errmsg[0] = 0;
				return EINVAL; /* Success */
			}
		}
	}

	if (changed)
		*changed = true;
	return 0;
}

static void
init_xml1(char *xml, char const *errmsg)
{
	input[0].xml = xml;
	input[0].errmsg = errmsg;
	memset(&input[1], 0, sizeof(input[1]));
}

static void
fetch_notif(char const *url, struct update_notification *notif)
{
	struct uri uri;
	bool changed;

	__URI_INIT(&uri, url);
	last_errmsg[0] = 0;

	ck_assert_int_eq(0, rrdpxml_fetch_notif(&uri, 0, &changed, notif));

	ck_assert_str_eq("", last_errmsg);
	ck_assert_int_eq(true, changed);
	ck_assert_str_eq(url, uri_str(notif->url));
}

static void
__fetch_notif_error(char const *url, char const *errmsg)
{
	struct uri uri;
	bool changed;
	struct update_notification notif;

	__URI_INIT(&uri, url);
	last_errmsg[0] = 0;

	ck_assert_int_eq(EINVAL, rrdpxml_fetch_notif(&uri, 0, &changed, &notif));

	ck_assert_str_eq(errmsg, last_errmsg);
}

static void
fetch_notif_error(char const *url)
{
	/*
	 * Error message must've been cleared by http_download(),
	 * and then no more errors
	 */
	__fetch_notif_error(url, "");
}

static void
ck_hash(char const *expected, struct rrdp_hash *actual)
{
	struct rrdp_hash expected_hash;

	ck_assert_int_eq(0, str2hash(expected, strlen(expected), &expected_hash));
	ck_assert_int_eq(true, actual->set);
	ck_assert(memcmp(expected_hash.bytes, actual->bytes, 32) == 0);
}

static void
ck_snapshot(struct file_metadata *actual, char const *url, char const *hash)
{
	ck_assert_str_eq(url, uri_str(&actual->uri));
	ck_hash(hash, &actual->hash);
}

static void
ck_delta(struct notification_delta *delta, char const *serial, char const *url,
    char const *hash)
{
	ck_assert_str_eq(serial, delta->serial.str);
	ck_assert_str_eq(url, uri_str(&delta->meta.uri));
	ck_hash(hash, &delta->meta.hash);
}

#define NOTIF(ss, sr) "<notification xmlns=\"http://www.ripe.net/rpki/rrdp\" version=\"1\" session_id=\"" ss "\" serial=\"" sr "\">"
#define HASH "0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD"
#define WS " \t\r\n" /* Whitespace */
#define CMT1 "<!---->" /* Comment */
#define CMT2 "<!-- -->"
#define CMT3 "<!-- Potato 🥔 " WS " Avocado 🥑 " WS "-->"

#define NOISY(NOISE) \
	NOISE "<" NOISE "notification" NOISE \
		"xmlns" NOISE "=" NOISE "\"http://www.ripe.net/rpki/rrdp\"" NOISE \
		"version" NOISE "=" NOISE "\"1\"" NOISE \
		"session_id" NOISE "=" NOISE "\"123123\"" NOISE \
		"serial" NOISE "=" NOISE "\"3\"" NOISE \
	">" NOISE \
		"<" NOISE "snapshot" NOISE \
			"uri" NOISE "=" NOISE "\"https://a/s.xml\"" NOISE \
			"hash" NOISE "=" NOISE "\"" HASH "\"" NOISE "/>" NOISE \
		"<" NOISE "delta" NOISE \
			"serial" NOISE "=" NOISE "\"3\"" NOISE \
			"uri" NOISE "=" NOISE "\"https://a/b/d3.xml\"" NOISE \
			"hash" NOISE "=" NOISE "\"" HASH "\"" NOISE "/>" NOISE \
	"</" NOISE "notification" NOISE ">" NOISE


START_TEST(notif_minimal)
{
	char *URL = "https://a/n.xml";
	char *XML = /* Zero redundant whitespace */
		NOTIF("123123", "3")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
		"</notification>";
	struct update_notification notif;

	init_xml1(XML, NULL);

	fetch_notif(URL, &notif);

	ck_assert_str_eq("123123", notif.session.session_id);
	ck_assert_str_eq("3", notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
	ck_assert_uint_eq(0, notif.deltas.len);

	notification_cleanup(&notif);
}
END_TEST

START_TEST(notif_2deltas)
{
	char *URL = "https://a/n.xml";
	char *XML = /* Zero redundant whitespace */
		NOTIF("123123", "3")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"3\" uri=\"https://a/b/d3.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"2\" uri=\"https://a/b/d2.xml\" hash=\"" HASH "\"/>"
		"</notification>";
	struct update_notification notif;

	init_xml1(XML, NULL);
	fetch_notif(URL, &notif);

	ck_assert_str_eq("123123", notif.session.session_id);
	ck_assert_str_eq("3", notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
	ck_assert_uint_eq(2, notif.deltas.len);
	ck_delta(&notif.deltas.arr[0], "3", "https://a/b/d3.xml", HASH);
	ck_delta(&notif.deltas.arr[1], "2", "https://a/b/d2.xml", HASH);

	notification_cleanup(&notif);
}
END_TEST

START_TEST(notif_1delta)
{
	char *URL = "https://a/n.xml";
	char *XML =
		NOTIF("123123", "3")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"3\" uri=\"https://a/b/d3.xml\" hash=\"" HASH "\"/>"
		"</notification>";
	struct update_notification notif;

	init_xml1(XML, NULL);
	fetch_notif(URL, &notif);

	ck_assert_str_eq("123123", notif.session.session_id);
	ck_assert_str_eq("3", notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
	ck_assert_uint_eq(1, notif.deltas.len);
	ck_delta(&notif.deltas.arr[0], "3", "https://a/b/d3.xml", HASH);

	notification_cleanup(&notif);
}
END_TEST

START_TEST(notif_redundant_whitespace)
{
	char *URL = "https://a/n.xml";
	char *XML = NOISY(WS);
	struct update_notification notif;

	init_xml1(XML, NULL);
	fetch_notif(URL, &notif);

	ck_assert_str_eq("123123", notif.session.session_id);
	ck_assert_str_eq("3", notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
	ck_assert_uint_eq(1, notif.deltas.len);
	ck_delta(&notif.deltas.arr[0], "3", "https://a/b/d3.xml", HASH);

	notification_cleanup(&notif);
}
END_TEST

START_TEST(notif_comments)
{
	char *URL = "https://a/n.xml";
	char *XML[] = { NOISY(CMT1), NOISY(CMT2), NOISY(CMT3) };
	struct update_notification notif;
	size_t i;

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		init_xml1(XML[i], NULL);
		fetch_notif(URL, &notif);

		ck_assert_str_eq("123123", notif.session.session_id);
		ck_assert_str_eq("3", notif.session.serial.str);
		ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
		ck_assert_uint_eq(1, notif.deltas.len);
		ck_delta(&notif.deltas.arr[0], "3", "https://a/b/d3.xml", HASH);

		notification_cleanup(&notif);
	}
}
END_TEST

START_TEST(notif_unterminated_comment)
{
	char *URL = "https://a/n.xml";
	char *XML = NOTIF("123123", "3") "<!-- abcd";

	init_xml1(XML, NULL);
	__fetch_notif_error(URL, "XML is unterminated");
}
END_TEST

START_TEST(notif_comment_boundaries)
{
	char *URL = "https://a/n.xml";
	char *XML[] = {
		NOTIF("01234567890123456", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("012345678901234567", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("0123456789012345678", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456789", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("012345678901234567890", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("0123456789012345678901", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456789012", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("012345678901234567890123", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("0123456789012345678901234", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456789012345", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("012345678901234567890123456", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("0123456789012345678901234567", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456789012345678", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("012345678901234567890123456789", "3") "<snapshot<!-- abc -->uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",

		NOTIF("01234567890123456", "3") "<snapshot uri=<!---->\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456", "3") "<snapshot uri= <!---->\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456", "3") "<snapshot uri=  <!---->\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456", "3") "<snapshot uri=   <!---->\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456", "3") "<snapshot uri=    <!---->\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456", "3") "<snapshot uri=     <!---->\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456", "3") "<snapshot uri=      <!---->\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456", "3") "<snapshot uri=       <!---->\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456", "3") "<snapshot uri=        <!---->\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("01234567890123456", "3") "<snapshot uri=         <!---->\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",

#define CMT "<!-- --> "
#define CMT10 CMT CMT CMT CMT CMT CMT CMT CMT CMT CMT
#define CMT100 CMT10 CMT10 CMT10 CMT10 CMT10 CMT10 CMT10 CMT10 CMT10 CMT10
		NOTIF("0123456789012345678901", "3") CMT100 CMT100 "<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
	};
	struct update_notification notif;
	array_index i;

	memset(&input, 0, sizeof(input));

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		init_xml1(XML[i], NULL);
		fetch_notif(URL, &notif);

		/* ck_assert_str_eq("123123", notif.session.session_id); */
		ck_assert_str_eq("3", notif.session.serial.str);
		ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
		ck_assert_uint_eq(0, notif.deltas.len);

		notification_cleanup(&notif);
	}
}
END_TEST

START_TEST(notif_lacks_snapshot)
{
	char *URL = "https://a/n.xml";
	char *XML = NOTIF("123123", "3") "</notification>";

	init_xml1(XML, "Notification lacks a Snapshot");
	fetch_notif_error(URL);
}
END_TEST

START_TEST(notif_not_ascii)
{
	char *URL = "https://a/n.xml";
	char *XML =
		NOTIF("123123", "3")
			"<snapshot uri=\"https://a/b/🧀.xml\" hash=\"" HASH "\"/>"
		"</notification>";

	/* Cheese UTF-8: 0xF0 0x9F 0xA7 0x80 */
	init_xml1(XML, "uri has illegal character: 0xf0");
	fetch_notif_error(URL);
}
END_TEST

#define SPCS "                                                      "
#define SPCS10 SPCS SPCS SPCS SPCS SPCS SPCS SPCS SPCS SPCS SPCS

/*
 * A logical phrase does not fit in the buffer because there's a bunch of
 * fraudulent whitespace.
 */
START_TEST(notif_too_much_whitespace)
{
	char *URL = "https://a/n.xml";
	char *XML[] = {
		SPCS10 NOTIF("123123", "3")    "<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("123123", "3") SPCS10    "<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("123123", "3") "<" SPCS10 "snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("123123", "3") "<snapshot"  SPCS10 "uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("123123", "3") "<snapshot uri" SPCS10 "=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("123123", "3") "<snapshot uri=" SPCS10 "\"https://a/s.xml\" hash=\"" HASH "\"/></notification>",
		NOTIF("123123", "3") "<snapshot uri=\"https://a/s.xml\"" SPCS10  "hash=\"" HASH "\"/></notification>",
		NOTIF("123123", "3") "<snapshot uri=\"https://a/s.xml\" hash" SPCS10 "=\"" HASH "\"/></notification>",
		NOTIF("123123", "3") "<snapshot uri=\"https://a/s.xml\" hash=" SPCS10 "\"" HASH "\"/></notification>",
		NOTIF("123123", "3") "<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"" SPCS10 "/></notification>",
		NOTIF("123123", "3") "<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>" SPCS10 "</notification>",
		NOTIF("123123", "3") "<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/></" SPCS10 "notification>",
		NOTIF("123123", "3") "<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification" SPCS10 ">",
		NOTIF("123123", "3") "<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/></notification>" SPCS10,
	};
	struct update_notification notif;
	size_t i;

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		init_xml1(XML[i], NULL);
		fetch_notif(URL, &notif);

		ck_assert_str_eq("123123", notif.session.session_id);
		ck_assert_str_eq("3", notif.session.serial.str);
		ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
		ck_assert_uint_eq(0, notif.deltas.len);

		notification_cleanup(&notif);
	}
}
END_TEST

START_TEST(notif_massive_whitespace)
{
	char *URL = "https://a/n.xml";
	char *XML =
		NOTIF("123123", "3")
			"<snapshot" SPCS10 SPCS10 SPCS10 SPCS10 SPCS10 SPCS10
				"uri=\"https://a/s.xml\" "
				"hash=\"" HASH "\"/>"
		"</notification>";
	struct update_notification notif;

	init_xml1(XML, NULL);
	fetch_notif(URL, &notif);

	ck_assert_str_eq("123123", notif.session.session_id);
	ck_assert_str_eq("3", notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
	ck_assert_uint_eq(0, notif.deltas.len);

	notification_cleanup(&notif);
}
END_TEST

START_TEST(notif_drip_feed_whitespace)
{
	char *URL = "https://a/n.xml";
	struct update_notification notif;
	size_t i;

	input[0].xml = NOTIF("123123", "3");
	input[1].xml = "<snapshot";
	input[2].xml = SPCS10;
	input[3].xml = SPCS10;
	input[4].xml = SPCS10;
	input[5].xml = SPCS10;
	input[6].xml = SPCS10;
	input[7].xml = SPCS10;
	input[8].xml = "uri=\"https://a/s.xml\" ";
	input[9].xml = "hash=\"" HASH "\"/>";
	input[10].xml = "</notification>";
	input[11].xml = NULL;
	for (i = 0; i < 12; i++)
		input[i].errmsg = NULL;

	fetch_notif(URL, &notif);

	ck_assert_str_eq("123123", notif.session.session_id);
	ck_assert_str_eq("3", notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
	ck_assert_uint_eq(0, notif.deltas.len);

	notification_cleanup(&notif);
}
END_TEST

START_TEST(notif_micro_drip_feed)
{
	char *URL = "https://a/n.xml";
	char *XML =
		NOTIF("123123", "3")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"3\" uri=\"https://a/b/d3.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"2\" uri=\"https://a/b/d2.xml\" hash=\"" HASH "\"/>"
		"</notification>";
	struct update_notification notif;

	init_xml1(XML, NULL);
	input[0].drip_feed = true;
	fetch_notif(URL, &notif);

	ck_assert_str_eq("123123", notif.session.session_id);
	ck_assert_str_eq("3", notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
	ck_assert_uint_eq(2, notif.deltas.len);
	ck_delta(&notif.deltas.arr[0], "3", "https://a/b/d3.xml", HASH);
	ck_delta(&notif.deltas.arr[1], "2", "https://a/b/d2.xml", HASH);

	notification_cleanup(&notif);
}
END_TEST

START_TEST(notif_long_token)
{
	char *URL = "https://a/n.xml";

	/*
	 * 15 characters: Approved by token fetcher, then rejected by parser
	 * because there's no expected tag named "a23456789012345"
	 */
	init_xml1(
		NOTIF("123123", "3")
			"<a23456789012345 uri=\"https://a/b/s.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		"Unexpected token: a23456789012345");
	fetch_notif_error(URL);

	/* 16 characters: Rejected by token fetcher because too long */
	init_xml1(
		NOTIF("123123", "3")
			"<a234567890123456 uri=\"https://a/b/s.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		"Token has too many characters: a234567890123456(...)");
	fetch_notif_error(URL);
}
END_TEST

START_TEST(notif_long_url)
{
	char *URL = "https://a/n.xml";
	struct update_notification notif;

#define CHR10 "123456789/"
#define CHR100 CHR10 CHR10 CHR10 CHR10 CHR10 CHR10 CHR10 CHR10 CHR10 CHR10

	/* 120 characters */
	init_xml1(
		NOTIF("123123", "3")
			/*              123456789AB (11)     12345678 9 (9)  */
			"<snapshot uri=\"https://a/" CHR100 "/aaa.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		NULL);

	fetch_notif(URL, &notif);
	ck_assert_str_eq("123123", notif.session.session_id);
	ck_assert_str_eq("3", notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/" CHR100 "/aaa.xml", HASH);
	ck_assert_uint_eq(0, notif.deltas.len);
	notification_cleanup(&notif);

	/* 121 characters */
	init_xml1(
		NOTIF("123123", "3")
			/*              123456789AB (11)     123456789 A (10)  */
			"<snapshot uri=\"https://a/" CHR100 "/aaaa.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		"Attribute value too long");
	fetch_notif_error(URL);
}
END_TEST

START_TEST(notif_long_serial)
{
	char *URL = "https://a/n.xml";
	struct update_notification notif;

#define CHR8 "12345678"
#define CHR64 CHR8 CHR8 CHR8 CHR8 CHR8 CHR8 CHR8 CHR8

	/* 64 characters */
	init_xml1(
		NOTIF("123123", CHR64)
			"<snapshot uri=\"https://a/n.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		NULL);

	fetch_notif(URL, &notif);
	ck_assert_str_eq("123123", notif.session.session_id);
	ck_assert_str_eq(CHR64, notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/n.xml", HASH);
	ck_assert_uint_eq(0, notif.deltas.len);
	notification_cleanup(&notif);

	/* 65 characters */
	init_xml1(
		NOTIF("123123", CHR64 "9")
			"<snapshot uri=\"https://a/n.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		"Notification serial is too long: 65 chars");
	fetch_notif_error(URL);
}
END_TEST

START_TEST(notif_sort_deltas)
{
	char *URL = "https://a/n.xml";
	char *XML[] = {
		NOTIF("123123", "22")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			/* Already sorted */
			"<delta serial=\"22\" uri=\"https://a/d22.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"21\" uri=\"https://a/d21.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"20\" uri=\"https://a/d20.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"19\" uri=\"https://a/d19.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"18\" uri=\"https://a/d18.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		NOTIF("123123", "22")
			/* Perfect backwards */
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"18\" uri=\"https://a/d18.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"19\" uri=\"https://a/d19.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"20\" uri=\"https://a/d20.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"21\" uri=\"https://a/d21.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"22\" uri=\"https://a/d22.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		NOTIF("123123", "22")
			/* Shuffled */
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"21\" uri=\"https://a/d21.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"19\" uri=\"https://a/d19.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"22\" uri=\"https://a/d22.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"18\" uri=\"https://a/d18.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"20\" uri=\"https://a/d20.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		NOTIF("123123", "22")
			/*
			 * Shuffled among discarded
			 * (config_get_rrdp_delta_threshold() is hardcoded
			 * in unit tests as 5)
			 */
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"22\" uri=\"https://a/d22.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"20\" uri=\"https://a/d20.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"15\" uri=\"https://a/d15.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"13\" uri=\"https://a/d13.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"18\" uri=\"https://a/d18.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"17\" uri=\"https://a/d17.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"21\" uri=\"https://a/d21.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"16\" uri=\"https://a/d16.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"19\" uri=\"https://a/d19.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"14\" uri=\"https://a/d14.xml\" hash=\"" HASH "\"/>"
		"</notification>",
	};
	struct update_notification notif;
	array_index i;

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		init_xml1(XML[i], NULL);
		fetch_notif(URL, &notif);

		ck_assert_str_eq("123123", notif.session.session_id);
		ck_assert_str_eq("22", notif.session.serial.str);
		ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
		ck_assert_uint_eq(5, notif.deltas.len);
		ck_delta(&notif.deltas.arr[0], "22", "https://a/d22.xml", HASH);
		ck_delta(&notif.deltas.arr[1], "21", "https://a/d21.xml", HASH);
		ck_delta(&notif.deltas.arr[2], "20", "https://a/d20.xml", HASH);
		ck_delta(&notif.deltas.arr[3], "19", "https://a/d19.xml", HASH);
		ck_delta(&notif.deltas.arr[4], "18", "https://a/d18.xml", HASH);

		notification_cleanup(&notif);
	}
}
END_TEST

START_TEST(notif_bad_deltas)
{
	char *URL = "https://a/n.xml";
	char *XML1[] = {
		NOTIF("123123", "22")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"23\" uri=\"https://a/d23.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"22\" uri=\"https://a/d22.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"21\" uri=\"https://a/d21.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		NOTIF("123123", "22")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"22\" uri=\"https://a/d22.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"21\" uri=\"https://a/d21.xml\" hash=\"" HASH "\"/>"
			/* Duplicate delta: Detected early because the array cannot be resized */
			"<delta serial=\"20\" uri=\"https://a/d20b.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"20\" uri=\"https://a/d20a.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"19\" uri=\"https://a/d19.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"18\" uri=\"https://a/d18.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		NOTIF("123123", "22")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			/* Notif vs delta serial mismatch: Detected early because obvious */
			"<delta serial=\"23\" uri=\"https://a/d23.xml\" hash=\"" HASH "\"/>"
		"</notification>",
	};
	char const *ERR1[] = {
		"Delta serial 23 is larger than Notification serial 22",
		"The Notification has duplicate delta serials",
		"Delta serial 23 is larger than Notification serial 22",
	};
	char *XML2[] = {
		NOTIF("123123", "22")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"22\" uri=\"https://a/d22.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"21\" uri=\"https://a/d21.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"20\" uri=\"https://a/d20.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"19\" uri=\"https://a/d19.xml\" hash=\"" HASH "\"/>"
			/* 18 missing */
			"<delta serial=\"17\" uri=\"https://a/d17.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		NOTIF("123123", "22")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"22\" uri=\"https://a/d22.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"21\" uri=\"https://a/d21.xml\" hash=\"" HASH "\"/>"
			/* Duplicate delta: Detected during the sort */
			"<delta serial=\"20\" uri=\"https://a/d20b.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"20\" uri=\"https://a/d20a.xml\" hash=\"" HASH "\"/>"
			"<delta serial=\"19\" uri=\"https://a/d19.xml\" hash=\"" HASH "\"/>"
		"</notification>",
		NOTIF("123123", "22")
			"<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			/* Notif vs delta serial mismatch: Detected during the sort */
			"<delta serial=\"21\" uri=\"https://a/d21.xml\" hash=\"" HASH "\"/>"
		"</notification>",
	};
	char const *ERR2[] = {
		"The serials listed in the Notification's deltas do not form a contiguous sequence",
		"Notification delta serial '20' is not unique",
		"Notification serial does not match highest delta serial: 22 != 21",
	};
	array_index i;

	for (i = 0; i < ARRAY_LEN(XML1); i++) {
		init_xml1(XML1[i], ERR1[i]);
		__fetch_notif_error(URL, "");
	}

	for (i = 0; i < ARRAY_LEN(XML2); i++) {
		init_xml1(XML2[i], NULL);
		__fetch_notif_error(URL, ERR2[i]);
	}
}
END_TEST

#undef NOTIF
#define NOTIF(x, v, ss, sr) "<notification xmlns=\"" x "\" version=\"" v "\" session_id=\"" ss "\" serial=\"" sr "\">"
#define SNAPSHOT(u, h) "<snapshot uri=\"" u "\" hash=\"" h "\"/> "

START_TEST(notif_bad_data_types)
{
	char *URL = "https://a/n.xml";
	char *XML[] = {
		NOTIF("http://wx3.ripe.net/rpki/rrdp", "1", "9df4b597-af9e-4dca-bdda", "3")
			SNAPSHOT("https://a/s.xml", HASH)
		"</notification>",
		NOTIF("http://www.ripe.net/rpki/rrdp", "2", "9df4b597-af9e-4dca-bdda", "3")
			SNAPSHOT("https://a/s.xml", HASH)
		"</notification>",
		NOTIF("http://www.ripe.net/rpki/rrdp", "1", "9*f4b597-af9e-4dca-bdda", "3")
			SNAPSHOT("https://a/s.xml", HASH)
		"</notification>",
		NOTIF("http://www.ripe.net/rpki/rrdp", "1", "9df4b597-af9e-4dca-bdda", "-1")
			SNAPSHOT("https://a/s.xml", HASH)
		"</notification>",
		NOTIF("http://www.ripe.net/rpki/rrdp", "1", "9df4b597-af9e-4dca-bdda", "3")
			SNAPSHOT("https://a/s.xml", "0g23456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD")
		"</notification>",
		NOTIF("http://www.ripe.net/rpki/rrdp", "1", "9df4b597-af9e-4dca-bdda", "3")
			SNAPSHOT("https://h[o]st/9d8/3/snapshot.xml", HASH)
		"</notification>",
		NOTIF("http://www.ripe.net/rpki/rrdp", "1", "9df4b597-af9e-4dca-bdda", "3")
			SNAPSHOT("https://ho st/9d-8/3/snapshot.xml", HASH)
		"</notification>",
		NOTIF("http://www.ripe.net/rpki/rrdp", "1", "9df4b597-af9e-4dca-bdda", "3")
			SNAPSHOT("https://different-host/9d-8/3/snapshot.xml", HASH)
		"</notification>"
	};
	char *ERR[] = {
		"<notification> xmlns is not http://www.ripe.net/rpki/rrdp: http://wx3.ripe.net/rpki/rrdp",
		"<notification> version is not 1: 2",
		"session_id has illegal character: *",
		"Negative serial: -1",
		"Not a valid hash: 0g23456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD",
		"'https://h[o]st/9d8/3/snapshot.xml' is not a valid URI: Illegal character in host component",
		"'https://ho st/9d-8/3/snapshot.xml' is not a valid URI: Illegal character in host component",
		"Notification 'https://a/n.xml' does not have the same origin as its Snapshot: https://different-host/9d-8/3/snapshot.xml",
	};
	size_t i;

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		init_xml1(XML[i], ERR[i]);
		fetch_notif_error(URL);
	}
}
END_TEST

static void
ck_file(char const *expected, char const *path)
{
	struct file_contents actual;
	ck_assert_int_eq(0, file_load(path, &actual, false));
	ck_assert_str_eq(expected, (char *)actual.buf);
	free(actual.buf);
}

static void
explode_snapshot(char const *ss_hash)
{
	struct uri url;
	struct update_notification notif = { 0 };
	struct files_ht files;
	struct cache_sequence seq;

	touch_dir("tmp");
	touch_dir("tmp/rrdp");
	ck_assert_int_eq(0, hash_setup());

	notif.session.session_id = "abcd";
	ck_assert_int_eq(0, str2serial("12", &notif.session.serial));
	__URI_INIT(&notif.snapshot.uri, "https://a/s.xml");
	ck_assert_int_eq(0, str2hash(ss_hash, strlen(ss_hash), &notif.snapshot.hash));
	notif.url = &url;
	__URI_INIT(&url, "https://a/n.xml");
	files.ht = NULL;
	cseq_init(&seq, "tmp/rrdp", 12, false);

	ck_assert_int_eq(0, rrdpxml_explode_snapshot(&notif, &files, &seq));

	hash_teardown();
}

static void
explode_snapshot_error(char const *errmsg)
{
	struct uri url;
	struct update_notification notif = { 0 };
	struct files_ht files;
	struct cache_sequence seq;

	touch_dir("tmp");
	touch_dir("tmp/rrdp");
	ck_assert_int_eq(0, hash_setup());

	notif.session.session_id = "abcd";
	ck_assert_int_eq(0, str2serial("12", &notif.session.serial));
	__URI_INIT(&notif.snapshot.uri, "https://a/s.xml");
	memset(&notif.snapshot.hash, 0, sizeof(notif.snapshot.hash));
	notif.snapshot.hash.set = true;
	notif.url = &url;
	__URI_INIT(&url, "https://a/n.xml");
	files.ht = NULL;
	cseq_init(&seq, "tmp/rrdp", 12, false);

	last_errmsg[0] = 0;
	ck_assert_int_eq(EINVAL, rrdpxml_explode_snapshot(&notif, &files, &seq));
	ck_assert_str_eq(errmsg, last_errmsg);

	hash_teardown();
}

START_TEST(snapshot_base64)
{
	init_xml1(
		"<snapshot xmlns=\"http://www.ripe.net/rpki/rrdp\" version=\"1\" session_id=\"abcd\" serial=\"12\">"
			"<publish uri=\"rsync://a/mod/c.cer\">ZXhhbXBsZTE=</publish>"
			"<publish uri=\"rsync://a/mod/m.mft\">ZXhhbXBsZTI=</publish>"
			"<publish uri=\"rsync://a/mod/c.crl\">ZXhhbXBsZTM=</publish>"
		"</snapshot>",
		NULL);

	explode_snapshot("5d1915d207dc35cf2e595daa014217698d241cc877ba0558ea3d7aa2472f9d54");

	ck_file("example1", "tmp/rrdp/C");
	ck_file("example2", "tmp/rrdp/D");
	ck_file("example3", "tmp/rrdp/E");
}
END_TEST

START_TEST(snapshot_base64_newlines)
{
	init_xml1(
		"<snapshot xmlns=\"http://www.ripe.net/rpki/rrdp\" version=\"1\" session_id=\"abcd\" serial=\"12\">\n"
		"	<publish uri=\"rsync://rpki.ripe.net/Alice/Bob.cer\">\n"
		"		TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4g\n"
		"		U3VzcGVuZGlzc2UgbWF4aW11cywgbWF1cmlzIGVnZXQgcGxhY2VyYXQgY29udmFsbGlzLCBkb2xv\n"
		"		ciBsb3JlbSB2ZWhpY3VsYSBmZWxpcywgbm9uIHZhcml1cyBlbmltIGRpYW0gdXQgdXJuYS4gTWFl\n"
		"		Y2VuYXMgaW50ZXJkdW0gZXggYXQgbW9sZXN0aWUgdGluY2lkdW50LiBJbiBzY2VsZXJpc3F1ZSBk\n"
		"		aWN0dW0gbmlzaSB2ZXN0aWJ1bHVtIHNlbXBlci4gQWxpcXVhbSBsaWd1bGEgbWksIHVsbGFtY29y\n"
		"		cGVyIHNlZCBsb3JlbSBub24sIGltcGVyZGlldCBpbnRlcmR1bSBzYXBpZW4uIEludGVnZXIgcG9y\n"
		"		dGEgdmVsIHJpc3VzIGluIGZyaW5naWxsYS4gTWF1cmlzIHZpdGFlIHRlbXBvciBsaWd1bGEuIFV0\n"
		"		IGV1aXNtb2QgbG9yZW0gYXJjdSwgYSB2aXZlcnJhIG1hZ25hIGJsYW5kaXQgc2l0IGFtZXQuIFF1\n"
		"		aXNxdWUgbWkgbmliaCwgc29kYWxlcyBhIHB1cnVzIG5vbiwgbGFjaW5pYSBlZmZpY2l0dXIgaXBz\n"
		"		dW0uIE51bmMgcXVpcyBzZW1wZXIgbWF1cmlzLCBxdWlzIGx1Y3R1cyBkdWkuIEZ1c2NlIHBsYWNl\n"
		"		cmF0IHNhcGllbiBpbiBkb2xvciBwaGFyZXRyYSwgdml0YWUgZWxlaWZlbmQgdG9ydG9yIHNvbGxp\n"
		"		Y2l0dWRpbi4gTWF1cmlzIGVnZXN0YXMgbmlzbCBpZCByaXN1cyByaG9uY3VzIGxvYm9ydGlzLiBG\n"
		"		dXNjZSBlZ2V0IGxhY3VzIGV0IGVsaXQgYXVjdG9yIHBvcnR0aXRvciBwZWxsZW50ZXNxdWUgYSBu\n"
		"		aXNpLiBEb25lYyBhY2N1bXNhbiBsZW8gdml0YWUgbWFnbmEgdmVoaWN1bGEgcG9ydHRpdG9yLiBO\n"
		"		dWxsYSBmaW5pYnVzIHZlbCBlcm9zIG5vbiBzb2xsaWNpdHVkaW4uIEludGVnZXIgdmVoaWN1bGEg\n"
		"		anVzdG8gc2VkIG51bmMgdGluY2lkdW50LCBldCBmZXJtZW50dW0gdGVsbHVzIHBlbGxlbnRlc3F1\n"
		"		ZS4KClNlZCBwdWx2aW5hciBldCBhcmN1IGFjIHN1c2NpcGl0LiBTZWQgbWF0dGlzIGZlcm1lbnR1\n"
		"		bSBwdXJ1cywgYSBzZW1wZXIgbG9yZW0gdGluY2lkdW50IGFjLiBBZW5lYW4gZWxlbWVudHVtIHVy\n"
		"		bmEgY29uZGltZW50dW0gZG9sb3IgcnV0cnVtLCBhYyBmcmluZ2lsbGEgcHVydXMgdWxsYW1jb3Jw\n"
		"		ZXIuIEludGVnZXIgc29kYWxlcyBtYWxlc3VhZGEgbGFjdXMsIHV0IHJob25jdXMgbGlndWxhIGRh\n"
		"		cGlidXMgZXQuIFByb2luIHZvbHV0cGF0IGV0IGRvbG9yIGluIHNlbXBlci4gU2VkIHZpdmVycmEg\n"
		"		aW4gZG9sb3IgbmVjIGZpbmlidXMuIEFlbmVhbiBzdXNjaXBpdCBsYWN1cyBhYyBkaWN0dW0gdGlu\n"
		"		<!-- IMPROMPTU STOWAWAY COMMENT! -->\n"
		"		Y2lkdW50LiBOdWxsYW0gYWMgc29sbGljaXR1ZGluIG5pc2ksIGF0IGhlbmRyZXJpdCBlbGl0LiBE\n"
		"		dWlzIGludGVyZHVtIG51bGxhIHR1cnBpcywgdml0YWUgZWdlc3RhcyBkaWFtIGNvbnNlcXVhdCB2\n"
		"		ZWwuIE51bGxhbSBlZmZpY2l0dXIgZXQgbWV0dXMgaWQgdGluY2lkdW50Lg==\n"
		"	</publish>\n"
		"</snapshot>",
		NULL);

	explode_snapshot("9911c6f780fc7c0a03ff74e44a52652764dd7071dcef426a5c6324971c160b89");

	ck_file("Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
	    "Suspendisse maximus, mauris eget placerat convallis, dolor lorem "
	    "vehicula felis, non varius enim diam ut urna. Maecenas interdum "
	    "ex at molestie tincidunt. In scelerisque dictum nisi vestibulum "
	    "semper. Aliquam ligula mi, ullamcorper sed lorem non, imperdiet "
	    "interdum sapien. Integer porta vel risus in fringilla. Mauris "
	    "vitae tempor ligula. Ut euismod lorem arcu, a viverra magna "
	    "blandit sit amet. Quisque mi nibh, sodales a purus non, lacinia "
	    "efficitur ipsum. Nunc quis semper mauris, quis luctus dui. Fusce "
	    "placerat sapien in dolor pharetra, vitae eleifend tortor "
	    "sollicitudin. Mauris egestas nisl id risus rhoncus lobortis. "
	    "Fusce eget lacus et elit auctor porttitor pellentesque a nisi. "
	    "Donec accumsan leo vitae magna vehicula porttitor. Nulla finibus "
	    "vel eros non sollicitudin. Integer vehicula justo sed nunc "
	    "tincidunt, et fermentum tellus pellentesque.\n\n"
	    "Sed pulvinar et arcu ac suscipit. Sed mattis fermentum purus, a "
	    "semper lorem tincidunt ac. Aenean elementum urna condimentum "
	    "dolor rutrum, ac fringilla purus ullamcorper. Integer sodales "
	    "malesuada lacus, ut rhoncus ligula dapibus et. Proin volutpat et "
	    "dolor in semper. Sed viverra in dolor nec finibus. Aenean "
	    "suscipit lacus ac dictum tincidunt. Nullam ac sollicitudin nisi, "
	    "at hendrerit elit. Duis interdum nulla turpis, vitae egestas "
	    "diam consequat vel. Nullam efficitur et metus id tincidunt.",
	    "tmp/rrdp/C");
}
END_TEST

START_TEST(snapshot_withdraw)
{
	init_xml1(
		"<snapshot xmlns=\"http://www.ripe.net/rpki/rrdp\" version=\"1\" session_id=\"abcd\" serial=\"12\">"
			"<publish uri=\"rsync://a/b/c.cer\">ZXhhbXBsZTE=</publish>"
			"<withdraw uri=\"rsync://a/b/d.mft\" hash=\"" HASH "\"/>"
			"<publish uri=\"rsync://a/b/e.crl\">ZXhhbXBsZTM=</publish>"
		"</snapshot>",
		"Unexpected token: withdraw");
	explode_snapshot_error("");
}
END_TEST

START_TEST(snapshot_bad_data_types)
{
	init_xml1(
		"<snapshot xmlns=\"http://www.ripe.net/rpki/rrdp\" version=\"1\" session_id=\"abcd\" serial=\"12\">"
			"<publish uri=\"rsync://a/b/c.cer\">ZXh^hbXBsZTE=</publish>"
		"</snapshot>",
		"Unrecognized base64 character: ^ (0x5e)");
	explode_snapshot_error("");
}
END_TEST

static void
explode_delta(char const *ss_hash)
{
	struct uri url;
	struct update_notification notif = { 0 };
	struct notification_delta delta;
	struct files_ht files;
	struct cache_sequence seq;

	touch_dir("tmp");
	touch_dir("tmp/rrdp");
	ck_assert_int_eq(0, hash_setup());

	notif.session.session_id = "abcd";
	ck_assert_int_eq(0, str2serial("12", &notif.session.serial));
	notif.url = &url;
	__URI_INIT(&url, "https://a/n.xml");
	ck_assert_int_eq(0, str2serial("10", &delta.serial));
	__URI_INIT(&delta.meta.uri, "https://a/d10.xml");
	ck_assert_int_eq(0, str2hash(ss_hash, strlen(ss_hash), &delta.meta.hash));
	files.ht = NULL;
	cseq_init(&seq, "tmp/rrdp", 12, false);

	ck_assert_int_eq(0, rrdpxml_explode_delta(&notif, &delta, &files, &seq));

	hash_teardown();
}

START_TEST(delta_minimal)
{
	init_xml1(
		"<delta xmlns=\"http://www.ripe.net/rpki/rrdp\" version=\"1\" session_id=\"abcd\" serial=\"10\">"
			"<publish uri=\"rsync://a/mod/c.cer\">ZXhhbXBsZTE=</publish>"
		"</delta>",
		NULL);

	explode_delta("be27b8719562b47d8645c46c7bc0eb4030aaf1fcbbb5548cc390058d852c73e2");

	ck_file("example1", "tmp/rrdp/C");
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *xml;

	xml = tcase_create("xml");
	tcase_add_test(xml, notif_minimal);
	tcase_add_test(xml, notif_2deltas);
	tcase_add_test(xml, notif_1delta);
	tcase_add_test(xml, notif_redundant_whitespace);
	tcase_add_test(xml, notif_comments);
	tcase_add_test(xml, notif_unterminated_comment);
	tcase_add_test(xml, notif_comment_boundaries);
	tcase_add_test(xml, notif_lacks_snapshot);
	tcase_add_test(xml, notif_not_ascii);
	tcase_add_test(xml, notif_too_much_whitespace);
	tcase_add_test(xml, notif_massive_whitespace);
	tcase_add_test(xml, notif_drip_feed_whitespace);
	tcase_add_test(xml, notif_micro_drip_feed);
	tcase_add_test(xml, notif_long_token);
	tcase_add_test(xml, notif_long_url);
	tcase_add_test(xml, notif_long_serial);
	tcase_add_test(xml, notif_sort_deltas);
	tcase_add_test(xml, notif_bad_deltas);
	tcase_add_test(xml, notif_bad_data_types);
	tcase_add_test(xml, snapshot_base64);
	tcase_add_test(xml, snapshot_base64_newlines);
	tcase_add_test(xml, snapshot_withdraw);
	tcase_add_test(xml, snapshot_bad_data_types);
	tcase_add_test(xml, delta_minimal);

	suite = suite_create("RRDP XML");
	suite_add_tcase(suite, xml);

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
