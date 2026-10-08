#include <check.h>

#define MAX_TKN_SIZE 120

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

#define NOTIF_URL "https://a/n.xml"
#define XMLDECL "<?xml version=\"1.0\" encoding=\"US-ASCII\"?>"
#define HTML_DT "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
#define NOTIF_DT "<!DOCTYPE notification>"
#define XMLNS "http://www.ripe.net/rpki/rrdp"
#define NOTIF_FULL(x, v, ss, sr) "<notification xmlns=\"" x "\" version=\"" v "\" session_id=\"" ss "\" serial=\"" sr "\">"
#define NOTIF_SERIAL(s) NOTIF_FULL(XMLNS, "1", "12-ab", s)
#define NOTIF_START NOTIF_SERIAL("23")
#define NSNAPSHOT "<snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>"
#define NDELTA(s) "<delta serial=\"" s "\" uri=\"https://a/d" s ".xml\" hash=\"" HASH "\"/>"
#define NOTIF_END "</notification>"
#define SNAPSHOT(u, h) "<snapshot uri=\"" u "\" hash=\"" h "\"/> "
#define HASH "0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD"
#define WS " \t\r\n" /* Whitespace */
#define CMT1 "<!---->" /* Comment */
#define CMT2 "<!-- -->"
#define CMT3 "<!-- Potato 🥔 " WS " Avocado 🥑 " WS "-->"
#define CMT4 "<!--Comment-->"
#define PI "<? ?>"

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
	input[0].drip_feed = false;
	memset(&input[1], 0, sizeof(input[1]));
}

static void
fetch_notif(struct update_notification *notif)
{
	struct uri uri;
	bool changed;

	__URI_INIT(&uri, NOTIF_URL);
	last_errmsg[0] = 0;

	ck_assert_int_eq(0, rrdpxml_fetch_notif(&uri, 0, &changed, notif));

	ck_assert_str_eq("", last_errmsg);
	ck_assert_int_eq(true, changed);
	ck_assert_str_eq(NOTIF_URL, uri_str(notif->url));
}

static void
__fetch_notif_error(char const *errmsg)
{
	struct uri uri;
	bool changed;
	struct update_notification notif;

	__URI_INIT(&uri, NOTIF_URL);
	last_errmsg[0] = 0;

	ck_assert_int_eq(EINVAL, rrdpxml_fetch_notif(&uri, 0, &changed, &notif));

	ck_assert_str_eq(errmsg, last_errmsg);
}

static void
fetch_notif_error(void)
{
	/*
	 * Error message must've been cleared by http_download(),
	 * and then no more errors
	 */
	__fetch_notif_error("");
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

static void
ck_notif(size_t deltas)
{
	struct update_notification notif;

	fetch_notif(&notif);

	ck_assert_str_eq("12-ab", notif.session.session_id);
	ck_assert_str_eq("23", notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
	ck_assert_uint_eq(deltas, notif.deltas.len);

	switch (deltas) {
	case 2: ck_delta(&notif.deltas.arr[1], "22", "https://a/d22.xml", HASH);
		/* No break */
	case 1: ck_delta(&notif.deltas.arr[0], "23", "https://a/d23.xml", HASH);
		/* No break */
	case 0: break;
	default:
		ck_abort_msg("Unimplemented delta count: %zu", deltas);
	}

	notification_cleanup(&notif);
}

START_TEST(notif_minimal)
{
	init_xml1(NOTIF_START NSNAPSHOT NOTIF_END, NULL);
	ck_notif(0);
}
END_TEST

START_TEST(notif_2deltas)
{
	init_xml1(NOTIF_START NSNAPSHOT NDELTA("23") NDELTA("22") NOTIF_END, NULL);
	ck_notif(2);
}
END_TEST

START_TEST(notif_1delta)
{
	init_xml1(NOTIF_START NSNAPSHOT NDELTA("23") NOTIF_END, NULL);
	ck_notif(1);
}
END_TEST

/* TODO (fine) Several noise locations not actually allowed by the grammar */
#define NOISY(NOISE) \
	NOISE "<" NOISE "notification" NOISE \
		"xmlns" NOISE "=" NOISE "\"" XMLNS "\"" NOISE \
		"version" NOISE "=" NOISE "\"1\"" NOISE \
		"session_id" NOISE "=" NOISE "\"12-ab\"" NOISE \
		"serial" NOISE "=" NOISE "\"23\"" NOISE \
	">" NOISE \
		"<" NOISE "snapshot" NOISE \
			"uri" NOISE "=" NOISE "\"https://a/s.xml\"" NOISE \
			"hash" NOISE "=" NOISE "\"" HASH "\"" NOISE "/>" NOISE \
		"<" NOISE "delta" NOISE \
			"serial" NOISE "=" NOISE "\"23\"" NOISE \
			"uri" NOISE "=" NOISE "\"https://a/d23.xml\"" NOISE \
			"hash" NOISE "=" NOISE "\"" HASH "\"" NOISE "/>" NOISE \
	"</" NOISE "notification" NOISE ">" NOISE

START_TEST(notif_redundant_whitespace)
{
	init_xml1(NOISY(WS), NULL);
	ck_notif(1);
}
END_TEST

START_TEST(notif_mandatory_whitespace)
{
	/*
	 * Compliance: According to the XML grammar, the whitespace between
	 * attributes is supposed to be mandatory.
	 */

	init_xml1(
		"<?xmlversion=\"1.0\" encoding=\"US-ASCII\"?>" NOTIF_DT
		NOTIF_START CMT4 NSNAPSHOT NDELTA("23") NOTIF_END,
		"Document has at least one Processing Instruction (<? ... ?>)."
	);
	fetch_notif_error();

	init_xml1(
		"<?xml version=\"1.0\"encoding=\"US-ASCII\"?>" NOTIF_DT
		NOTIF_START CMT4 NSNAPSHOT NDELTA("23") NOTIF_END,
		NULL
	);
	ck_notif(1); /* Not compliant, fine */

	init_xml1(
		XMLDECL "<!DOCTYPEnotification>"
		NOTIF_START CMT4 NSNAPSHOT NDELTA("23") NOTIF_END,
		"(Line 1) Unexpected token: '<!DOCTYPEn'"
	);
	fetch_notif_error();

	init_xml1(
		XMLDECL NOTIF_DT
		"<notificationxmlns=\"" XMLNS "\" version=\"1\" session_id=\"12-ab\" serial=\"23\">"
			CMT4 NSNAPSHOT NDELTA("23")
		NOTIF_END,
		"(Line 1) Name has too many characters: notificationx(...)"
	);
	fetch_notif_error();

	init_xml1(
		XMLDECL NOTIF_DT
		"<notification xmlns=\"" XMLNS "\"version=\"1\" session_id=\"12-ab\" serial=\"23\">"
			CMT4 NSNAPSHOT NDELTA("23")
		NOTIF_END,
		NULL
	);
	ck_notif(1); /* Not compliant, fine */

	init_xml1(
		XMLDECL NOTIF_DT
		"<notification xmlns=\"" XMLNS "\" version=\"1\"session_id=\"12-ab\" serial=\"23\">"
			CMT4 NSNAPSHOT NDELTA("23")
		NOTIF_END,
		NULL
	);
	ck_notif(1); /* Not compliant, fine */

	init_xml1(
		XMLDECL NOTIF_DT
		"<notification xmlns=\"" XMLNS "\" version=\"1\" session_id=\"12-ab\"serial=\"23\">"
			CMT4 NSNAPSHOT NDELTA("23")
		NOTIF_END,
		NULL
	);
	ck_notif(1); /* Not compliant, fine */

	init_xml1(
		XMLDECL NOTIF_DT
		NOTIF_START
			CMT4
			"<snapshoturi=\"https://a/s.xml\" hash=\"" HASH "\"/>"
			NDELTA("23")
		NOTIF_END,
		"(Line 1) Unexpected token: snapshoturi"
	);
	fetch_notif_error();

	init_xml1(
		XMLDECL NOTIF_DT
		NOTIF_START
			CMT4
			"<snapshot uri=\"https://a/s.xml\"hash=\"" HASH "\"/>"
			NDELTA("23")
		NOTIF_END,
		NULL
	);
	ck_notif(1); /* Not compliant, fine */

	init_xml1(
		XMLDECL NOTIF_DT
		NOTIF_START
			CMT4
			NSNAPSHOT
			"<deltaserial=\"23\" uri=\"https://a/d23.xml\" hash=\"" HASH "\"/>"
		NOTIF_END,
		"(Line 1) Unexpected token: deltaserial"
	);
	fetch_notif_error();

	init_xml1(
		XMLDECL NOTIF_DT
		NOTIF_START
			CMT4
			NSNAPSHOT
			"<delta serial=\"23\"uri=\"https://a/d23.xml\" hash=\"" HASH "\"/>"
		NOTIF_END,
		NULL
	);
	ck_notif(1); /* Not compliant, fine */

	init_xml1(
		XMLDECL NOTIF_DT
		NOTIF_START
			CMT4
			NSNAPSHOT
			"<delta serial=\"23\" uri=\"https://a/d23.xml\"hash=\"" HASH "\"/>"
		NOTIF_END,
		NULL
	);
	ck_notif(1); /* Not compliant, fine */
}
END_TEST

#undef NOISY
#define NOISY(NOISE) NOTIF_START NOISE NSNAPSHOT NOISE NDELTA("23") NOISE NOTIF_END NOISE

START_TEST(notif_comments)
{
	char *XML[] = {
		NOISY(CMT1),
		NOISY(CMT2),
		NOISY(CMT3),
		CMT1 NOISY(CMT1),
		CMT2 NOISY(CMT2),
		CMT3 NOISY(CMT3),
		XMLDECL CMT1 NOTIF_DT CMT1 NOISY(CMT1),
		XMLDECL CMT2 NOTIF_DT CMT2 NOISY(CMT2),
		XMLDECL CMT3 NOTIF_DT CMT3 NOISY(CMT3),
	};
	size_t i;

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		init_xml1(XML[i], NULL);
		ck_notif(1);
	}
}
END_TEST

START_TEST(notif_unterminated_comment)
{
	init_xml1(NOTIF_START "<!-- abcd", NULL);
	__fetch_notif_error("XML is unterminated");
}
END_TEST

#define PREFIX "<notification xmlns=\"" XMLNS "\" version=\"1\" session_id=\"12-ab\" serial=\"23\""
#define SUFFIX "snapshot uri=\"https://a/s.xml\" hash=\"" HASH "\"/>" NOTIF_END

START_TEST(notif_comment_boundaries)
{
	char *XML[][2] = {
		{ PREFIX "><!-- abc --><", "" SUFFIX },
		{ PREFIX "><!-- abc -->", "<" SUFFIX },
		{ PREFIX "><!-- abc --", "><" SUFFIX },
		{ PREFIX "><!-- abc -", "-><" SUFFIX },
		{ PREFIX "><!-- abc ", "--><" SUFFIX },
		{ PREFIX "><!-- abc", " --><" SUFFIX },
		{ PREFIX "><!-- ab", "c --><" SUFFIX },
		{ PREFIX "><!-- a", "bc --><" SUFFIX },
		{ PREFIX "><!-- ", "abc --><" SUFFIX },
		{ PREFIX "><!--", " abc --><" SUFFIX },
		{ PREFIX "><!-", "- abc --><" SUFFIX },
		{ PREFIX "><!", "-- abc --><" SUFFIX },
		{ PREFIX "><", "!-- abc --><" SUFFIX },
		{ PREFIX ">", "<!-- abc --><" SUFFIX },
		{ PREFIX "", "><!-- abc --><" SUFFIX },

		{ PREFIX "><!----><", "" SUFFIX },
		{ PREFIX "><!---->", "<" SUFFIX },
		{ PREFIX "><!----", "><" SUFFIX },
		{ PREFIX "><!---", "-><" SUFFIX },
		{ PREFIX "><!--", "--><" SUFFIX },
		{ PREFIX "><!-", "---><" SUFFIX },
		{ PREFIX "><!", "----><" SUFFIX },
		{ PREFIX "><", "!----><" SUFFIX },
		{ PREFIX ">", "<!----><" SUFFIX },
		{ PREFIX "", "><!----><" SUFFIX },
	};
	array_index i;

	memset(&input, 0, sizeof(input));

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		input[0].xml = XML[i][0];
		input[1].xml = XML[i][1];
		ck_notif(0);
	}

	input[0].xml = PREFIX;
	input[1].xml = "><!-- -->";
	input[2].xml = "<!-- --><";
	input[3].xml = "!-- --><!";
	input[4].xml = "-- --><!-";
	input[5].xml = "- --><!--";
	input[6].xml = " --><!-- ";
	input[7].xml = "--><!-- -";
	input[8].xml = "-><!-- --";
	input[9].xml = "><!-- -->";
	input[10].xml = "<!-- --><";
	input[11].xml = SUFFIX;
	ck_notif(0);

	input[0].xml = PREFIX "><!-- abc --><" SUFFIX;
	input[0].drip_feed = true;
	input[1].xml = NULL;
	ck_notif(0);
}
END_TEST

START_TEST(notif_lacks_snapshot)
{
	init_xml1(NOTIF_START NOTIF_END, "Notification lacks a Snapshot");
	fetch_notif_error();
}
END_TEST

START_TEST(notif_not_ascii)
{
	/* Cheese UTF-8: 0xF0 0x9F 0xA7 0x80 */
	init_xml1(
		NOTIF_START "\n"
			"<snapshot\n"
				"uri=\"https://a/🧀.xml\"\n"
				"hash=\"" HASH "\"/>\n"
		NOTIF_END,
		"(Line 3) uri has illegal character: 0xf0"
	);
	fetch_notif_error();
}
END_TEST

START_TEST(notif_buffer_interruptions)
{
	char *XML =
		"<?xml version=\"1.0\"\tencoding=\"US-ASCII\"\n?>\n"
		"<!DOCTYPE   notification >\n"
		NOTIF_START "\n"
			"<!-- Comment -->\t\n"
			NSNAPSHOT "\t"
			NDELTA("23") " "
		NOTIF_END " \t ";
	static char HALF1[512];
	static char HALF2[512];
	size_t i, n;

	memset(&input, 0, sizeof(input));
	memset(HALF1, 0, sizeof(HALF1));
	strcpy(HALF2, XML);

	n = strlen(XML);
	for (i = 0; i < n; i++) {
		HALF1[i] = HALF2[i];
		input[0].xml = HALF1;
		input[1].xml = HALF2 + i + 1u;
		ck_notif(1);
	}
}
END_TEST

#define SPCS "                                                      "
#define SPCS10 SPCS SPCS SPCS SPCS SPCS SPCS SPCS SPCS SPCS SPCS

START_TEST(notif_massive_whitespace)
{
	init_xml1(
		NOTIF_START
			"<snapshot" SPCS10 SPCS10 SPCS10 SPCS10 SPCS10 SPCS10
				"uri=\"https://a/s.xml\" "
				"hash=\"" HASH "\"/>"
		NOTIF_END,
		NULL
	);
	ck_notif(0);
}
END_TEST

START_TEST(notif_drip_feed_whitespace)
{
	memset(&input, 0, sizeof(input));
	input[0].xml = NOTIF_START;
	input[1].xml = "<snapshot";
	input[2].xml = SPCS10;
	input[3].xml = SPCS10;
	input[4].xml = SPCS10;
	input[5].xml = SPCS10;
	input[6].xml = SPCS10;
	input[7].xml = SPCS10;
	input[8].xml = "uri=\"https://a/s.xml\" ";
	input[9].xml = "hash=\"" HASH "\"/>";
	input[10].xml = NOTIF_END;
	input[11].xml = NULL;

	ck_notif(0);
}
END_TEST

START_TEST(notif_micro_drip_feed)
{
	init_xml1(NOTIF_START NSNAPSHOT NDELTA("23") NDELTA("22") NOTIF_END, NULL);
	input[0].drip_feed = true;
	ck_notif(2);
}
END_TEST

START_TEST(notif_long_token)
{
	/*
	 * 12 characters: Approved by token fetcher, then rejected by parser
	 * because there's no expected tag named "a23456789012"
	 */
	init_xml1(
		NOTIF_START "\n"
			"<a23456789012 uri=\"https://a/s.xml\" hash=\"" HASH "\"/>\n"
		NOTIF_END,
		"(Line 2) Unexpected token: a23456789012"
	);
	fetch_notif_error();

	/*
	 * 13 characters: Rejected by token fetcher because too long.
	 * 13th character could be printed because the parser needed to find out
	 * whether it was a name character or not.
	 */
	init_xml1(
		NOTIF_START "\n"
			"<a234567890123 uri=\"https://a/s.xml\" hash=\"" HASH "\"/>\n"
		NOTIF_END,
		"(Line 2) Name has too many characters: a234567890123(...)"
	);
	fetch_notif_error();

	/*
	 * 14 characters: Rejected by token fetcher because too long.
	 * 14th character is not printed because the token fetcher only got to
	 * the 13th one.
	 */
	init_xml1(
		NOTIF_START "\n"
			"<a2345678901234 uri=\"https://a/s.xml\" hash=\"" HASH "\"/>\n"
		NOTIF_END,
		"(Line 2) Name has too many characters: a234567890123(...)"
	);
	fetch_notif_error();
}
END_TEST

START_TEST(notif_long_url)
{
	struct update_notification notif;

#define CHR10 "123456789/"
#define CHR100 CHR10 CHR10 CHR10 CHR10 CHR10 CHR10 CHR10 CHR10 CHR10 CHR10

	/* 120 characters */
	init_xml1(
		NOTIF_START
			/*              123456789AB (11)     12345678 9 (9)  */
			"<snapshot uri=\"https://a/" CHR100 "/aaa.xml\" hash=\"" HASH "\"/>"
		NOTIF_END,
		NULL
	);
	fetch_notif(&notif);
	ck_assert_str_eq("12-ab", notif.session.session_id);
	ck_assert_str_eq("23", notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/" CHR100 "/aaa.xml", HASH);
	ck_assert_uint_eq(0, notif.deltas.len);
	notification_cleanup(&notif);

	/* 121 characters */
	init_xml1(
		NOTIF_START "\n"
			/*              123456789AB (11)     123456789 A (10)  */
			"<snapshot\n"
				"uri=\"https://a/" CHR100 "/aaaa.xml\"\n"
				"hash=\"" HASH "\"/>\n"
		NOTIF_END,
		"(Line 3) Attribute value too long"
	);
	fetch_notif_error();
}
END_TEST

START_TEST(notif_long_serial)
{
	struct update_notification notif;

#define CHR8 "12345678"
#define CHR64 CHR8 CHR8 CHR8 CHR8 CHR8 CHR8 CHR8 CHR8

	/* 64 characters */
	init_xml1(NOTIF_SERIAL(CHR64) NSNAPSHOT NOTIF_END, NULL);

	fetch_notif(&notif);
	ck_assert_str_eq("12-ab", notif.session.session_id);
	ck_assert_str_eq(CHR64, notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
	ck_assert_uint_eq(0, notif.deltas.len);
	notification_cleanup(&notif);

	/* 65 characters */
	init_xml1(
		NOTIF_SERIAL(CHR64 "9") "\n" NSNAPSHOT "\n" NOTIF_END,
		"(Line 1) <notification> serial is too long: 65 chars"
	);
	fetch_notif_error();
}
END_TEST

START_TEST(notif_long_delta_serial)
{
	char *XML;
	struct update_notification notif;

	/* 64 characters */
	XML =	NOTIF_SERIAL(CHR64)
			NSNAPSHOT
			"<delta serial=\"" CHR64 "\" "
				"uri=\"https://a/d64.xml\" "
				"hash=\"" HASH "\"/>"
		NOTIF_END;
	init_xml1(XML, NULL);

	fetch_notif(&notif);
	ck_assert_str_eq("12-ab", notif.session.session_id);
	ck_assert_str_eq(CHR64, notif.session.serial.str);
	ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
	ck_assert_uint_eq(1, notif.deltas.len);
	ck_delta(&notif.deltas.arr[0], CHR64, "https://a/d64.xml", HASH);
	notification_cleanup(&notif);

	/* 65 characters */
	XML =	NOTIF_START "\n"
			NSNAPSHOT "\n"
			"<delta serial=\"" CHR64 "9\" "
				"uri=\"https://a/d65.xml\" "
				"hash=\"" HASH "\"/>\n"
		NOTIF_END;
	init_xml1(XML, "(Line 3) <delta> serial is too long: 65 chars");
	fetch_notif_error();
}
END_TEST

START_TEST(notif_sort_deltas)
{
	char *XML[] = {
		NOTIF_START
			NSNAPSHOT
			/* Already sorted */
			NDELTA("23")
			NDELTA("22")
			NDELTA("21")
			NDELTA("20")
			NDELTA("19")
		NOTIF_END,
		NOTIF_START
			/* Perfect backwards */
			NSNAPSHOT
			NDELTA("19")
			NDELTA("20")
			NDELTA("21")
			NDELTA("22")
			NDELTA("23")
		NOTIF_END,
		NOTIF_START
			/* Shuffled */
			NSNAPSHOT
			NDELTA("22")
			NDELTA("20")
			NDELTA("23")
			NDELTA("19")
			NDELTA("21")
		NOTIF_END,
		NOTIF_START
			/*
			 * Shuffled among discarded
			 * (config_get_rrdp_delta_threshold() is hardcoded
			 * in unit tests as 5)
			 */
			NSNAPSHOT
			NDELTA("23")
			NDELTA("21")
			NDELTA("16")
			NDELTA("14")
			NDELTA("19")
			NDELTA("18")
			NDELTA("22")
			NDELTA("17")
			NDELTA("20")
			NDELTA("15")
		NOTIF_END,
	};
	struct update_notification notif;
	array_index i;

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		init_xml1(XML[i], NULL);
		fetch_notif(&notif);

		ck_assert_str_eq("12-ab", notif.session.session_id);
		ck_assert_str_eq("23", notif.session.serial.str);
		ck_snapshot(&notif.snapshot, "https://a/s.xml", HASH);
		ck_assert_uint_eq(5, notif.deltas.len);
		ck_delta(&notif.deltas.arr[0], "23", "https://a/d23.xml", HASH);
		ck_delta(&notif.deltas.arr[1], "22", "https://a/d22.xml", HASH);
		ck_delta(&notif.deltas.arr[2], "21", "https://a/d21.xml", HASH);
		ck_delta(&notif.deltas.arr[3], "20", "https://a/d20.xml", HASH);
		ck_delta(&notif.deltas.arr[4], "19", "https://a/d19.xml", HASH);

		notification_cleanup(&notif);
	}
}
END_TEST

START_TEST(notif_bad_deltas)
{
	char *XML1[] = {
		NOTIF_START "\n"
			NSNAPSHOT "\n"
			NDELTA("24") "\n"
			NDELTA("23") "\n"
			NDELTA("22") "\n"
		NOTIF_END,
		NOTIF_START "\n"
			NSNAPSHOT "\n"
			NDELTA("23") "\n"
			NDELTA("22") "\n"
			/* Duplicate delta: Detected early because the array cannot be resized */
			NDELTA("21") "\n"
			NDELTA("21") "\n"
			NDELTA("20") "\n"
			NDELTA("19") "\n"
		NOTIF_END,
		NOTIF_START "\n"
			NSNAPSHOT "\n"
			/* Notif vs delta serial mismatch: Detected early because obvious */
			NDELTA("24") "\n"
		NOTIF_END,
	};
	char const *ERR1[] = {
		"(Line 3) Delta serial 24 is larger than Notification serial 23",
		"The Notification has duplicate delta serials",
		"(Line 3) Delta serial 24 is larger than Notification serial 23",
	};
	char *XML2[] = {
		NOTIF_START "\n"
			NSNAPSHOT "\n"
			NDELTA("23") "\n"
			NDELTA("22") "\n"
			NDELTA("21") "\n"
			NDELTA("20") "\n"
			/* 19 missing */
			NDELTA("18") "\n"
		NOTIF_END,
		NOTIF_START "\n"
			NSNAPSHOT "\n"
			NDELTA("23") "\n"
			NDELTA("22") "\n"
			/* Duplicate delta: Detected during the sort */
			NDELTA("21") "\n"
			NDELTA("21") "\n"
			NDELTA("20") "\n"
		NOTIF_END,
		NOTIF_START "\n"
			NSNAPSHOT "\n"
			/* Notif vs delta serial mismatch: Detected during the sort */
			NDELTA("22") "\n"
		NOTIF_END,
	};
	char const *ERR2[] = {
		"The serials listed in the Notification's deltas do not form a contiguous sequence",
		"Notification delta serial '21' is not unique",
		"Notification serial does not match highest delta serial: 23 != 22",
	};
	array_index i;

	for (i = 0; i < ARRAY_LEN(XML1); i++) {
		init_xml1(XML1[i], ERR1[i]);
		fetch_notif_error();
	}

	for (i = 0; i < ARRAY_LEN(XML2); i++) {
		init_xml1(XML2[i], NULL);
		__fetch_notif_error(ERR2[i]);
	}
}
END_TEST

START_TEST(notif_bad_data_types)
{
	char *XML[] = {
		NOTIF_FULL("http://wx3.ripe.net/rpki/rrdp", "1", "9df4b597-af9e-4dca-bdda", "3") "\n"
			SNAPSHOT("https://a/s.xml", HASH) "\n"
		NOTIF_END,
		NOTIF_FULL(XMLNS, "2", "9df4b597-af9e-4dca-bdda", "3") "\n"
			SNAPSHOT("https://a/s.xml", HASH) "\n"
		NOTIF_END,
		NOTIF_FULL(XMLNS, "1", "9*f4b597-af9e-4dca-bdda", "3") "\n"
			SNAPSHOT("https://a/s.xml", HASH) "\n"
		NOTIF_END,
		NOTIF_FULL(XMLNS, "1", "9df4b597-af9e-4dca-bdda", "-1") "\n"
			SNAPSHOT("https://a/s.xml", HASH) "\n"
		NOTIF_END,
		NOTIF_FULL(XMLNS, "1", "9df4b597-af9e-4dca-bdda", "3") "\n"
			SNAPSHOT("https://a/s.xml", "0g23456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD") "\n"
		NOTIF_END,
		NOTIF_FULL(XMLNS, "1", "9df4b597-af9e-4dca-bdda", "3") "\n"
			SNAPSHOT("https://h[o]st/9d8/3/snapshot.xml", HASH) "\n"
		NOTIF_END,
		NOTIF_FULL(XMLNS, "1", "9df4b597-af9e-4dca-bdda", "3") "\n"
			SNAPSHOT("https://ho st/9d-8/3/snapshot.xml", HASH) "\n"
		NOTIF_END,
		NOTIF_FULL(XMLNS, "1", "9df4b597-af9e-4dca-bdda", "3") "\n"
			SNAPSHOT("https://different-host/9d-8/3/snapshot.xml", HASH) "\n"
		NOTIF_END,
	};
	char *ERR[] = {
		"(Line 1) <notification> xmlns is not " XMLNS ": http://wx3.ripe.net/rpki/rrdp",
		"(Line 1) <notification> version is not 1: 2",
		"(Line 1) session_id has illegal character: *",
		"(Line 1) Negative serial: -1",
		"(Line 2) Not a valid hash: 0g23456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD",
		"(Line 2) 'https://h[o]st/9d8/3/snapshot.xml' is not a valid URI: Illegal character in host component",
		"(Line 2) 'https://ho st/9d-8/3/snapshot.xml' is not a valid URI: Illegal character in host component",
		"(Line 2) Notification 'https://a/n.xml' does not have the same origin as its Snapshot: https://different-host/9d-8/3/snapshot.xml",
	};
	size_t i;

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		init_xml1(XML[i], ERR[i]);
		fetch_notif_error();
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
	__URI_INIT(&url, NOTIF_URL);
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
	__URI_INIT(&url, NOTIF_URL);
	files.ht = NULL;
	cseq_init(&seq, "tmp/rrdp", 12, false);

	last_errmsg[0] = 0;
	ck_assert_int_eq(EINVAL, rrdpxml_explode_snapshot(&notif, &files, &seq));
	ck_assert_str_eq(errmsg, last_errmsg);

	hash_teardown();
}

START_TEST(notif_xml_hdrs)
{
	char *XML[] = {
		XMLDECL
		NOTIF_START
			SNAPSHOT("https://a/s.xml", HASH)
		NOTIF_END,
		/* TODO (test) Maybe check the warning message this prints */
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		NOTIF_START
			SNAPSHOT("https://a/s.xml", HASH)
		NOTIF_END,
		NOTIF_DT
		NOTIF_START
			SNAPSHOT("https://a/s.xml", HASH)
		NOTIF_END,
		"<?xml version=\"1.1\" encoding=\"US-ASCII\"?>"
		"<!DOCTYPE NOTIFICATION>"
		NOTIF_START
			SNAPSHOT("https://a/s.xml", HASH)
		NOTIF_END,
	};
	size_t i;

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		init_xml1(XML[i], NULL);
		ck_notif(0);
	}
}
END_TEST

START_TEST(notif_pi_boundaries)
{
#undef PREFIX
#undef SUFFIX
#define PREFIX "<?xml version=\"1.0\" encoding=\"US-ASCII\""
#define SUFFIX "DOCTYPE html><html/>"

	char *XML[][2] = {
		{ PREFIX "", "?><? ... ?><!" SUFFIX },
		{ PREFIX "?", "><? ... ?><!" SUFFIX },
		{ PREFIX "?>", "<? ... ?><!" SUFFIX },
		{ PREFIX "?><", "? ... ?><!" SUFFIX },
		{ PREFIX "?><?", " ... ?><!" SUFFIX },
		{ PREFIX "?><? ", "... ?><!" SUFFIX },
		{ PREFIX "?><? .", ".. ?><!" SUFFIX },
		{ PREFIX "?><? ..", ". ?><!" SUFFIX },
		{ PREFIX "?><? ...", " ?><!" SUFFIX },
		{ PREFIX "?><? ... ", "?><!" SUFFIX },
		{ PREFIX "?><? ... ?", "><!" SUFFIX },
		{ PREFIX "?><? ... ?>", "<!" SUFFIX },
		{ PREFIX "?><? ... ?><", "!" SUFFIX },
		{ PREFIX "?><? ... ?><!", "" SUFFIX },

		{ PREFIX "", "?><?\?><!" SUFFIX },
		{ PREFIX "?", "><?\?><!" SUFFIX },
		{ PREFIX "?>", "<?\?><!" SUFFIX },
		{ PREFIX "?><", "?\?><!" SUFFIX },
		{ PREFIX "?><?", "\?><!" SUFFIX },
		{ PREFIX "?><?\?", "><!" SUFFIX },
		{ PREFIX "?><?\?>", "<!" SUFFIX },
		{ PREFIX "?><?\?><", "!" SUFFIX },
		{ PREFIX "?><?\?><!", "" SUFFIX },
	};
	array_index i;

	memset(&input, 0, sizeof(input));

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		input[0].xml = XML[i][0];
		input[1].xml = XML[i][1];
		input[2].xml = NULL;
		__fetch_notif_error("The document was not an RRDP Notification.");
	}

	input[0].xml = PREFIX "?";
	input[1].xml = "><? ?>";
	input[2].xml = "<? ?><";
	input[3].xml = "? ?><?";
	input[4].xml = " ?><? ";
	input[5].xml = "?><? ?";
	input[6].xml = "><!" SUFFIX;
	__fetch_notif_error("The document was not an RRDP Notification.");

	input[0].xml = PREFIX "?><? ?><!" SUFFIX;
	input[0].drip_feed = true;
	input[1].xml = NULL;
	__fetch_notif_error("The document was not an RRDP Notification.");
}
END_TEST

START_TEST(notif_pi_rejected)
{
	char *XML[] = {
		XMLDECL
		"<? ?>"
		NOTIF_START
			SNAPSHOT("https://a/s.xml", HASH)
		NOTIF_END,
		XMLDECL
		"<? ?>"
		NOTIF_DT
		NOTIF_START
			SNAPSHOT("https://a/s.xml", HASH)
		NOTIF_END,
	};
	array_index i;

	memset(&input, 0, sizeof(input));

	for (i = 0; i < ARRAY_LEN(XML); i++) {
		init_xml1(XML[i], "Document has at least one Processing Instruction (<? ... ?>).");
		fetch_notif_error();
	}
}
END_TEST

#define HTML_TAIL \
	"<html><head>\n" \
	"<title>302 Found</title>\n" \
	"</head><body>\n" \
	"<h1>Found</h1>\n" \
	"<p>The doc has moved <a href=\"https://a/n2.xml\">here</a>.</p>\n" \
	"</body></html>"
#define NOTIF_TAIL \
	NOTIF_START(XMLNS, "1", "abcd", "3") \
		SNAPSHOT("https://a/s.xml", HASH) \
	NOTIF_END

START_TEST(notif_not_rrdp)
{
	init_xml1(HTML_TAIL, NULL);
	__fetch_notif_error("The document was not an RRDP Notification.");
	init_xml1(XMLDECL HTML_TAIL, NULL);
	__fetch_notif_error("The document was not an RRDP Notification.");
	init_xml1(XMLDECL PI HTML_TAIL, NULL);
	__fetch_notif_error("The document was not an RRDP Notification.");
	init_xml1(HTML_DT HTML_TAIL, NULL);
	__fetch_notif_error("The document was not an RRDP Notification.");
	init_xml1(PI HTML_DT HTML_TAIL, NULL);
	__fetch_notif_error("The document was not an RRDP Notification.");
	init_xml1(HTML_DT PI HTML_TAIL, NULL);
	__fetch_notif_error("The document was not an RRDP Notification.");
	init_xml1(PI HTML_DT PI HTML_TAIL, NULL);
	__fetch_notif_error("The document was not an RRDP Notification.");
	init_xml1(XMLDECL HTML_DT HTML_TAIL, NULL);
	__fetch_notif_error("The document was not an RRDP Notification.");
	init_xml1(XMLDECL PI PI CMT2 CMT2 PI CMT2 HTML_DT PI PI CMT2 CMT2 PI CMT2 HTML_TAIL, NULL);
	__fetch_notif_error("The document was not an RRDP Notification.");

	init_xml1(XMLDECL "\n" XMLDECL "\n" NOTIF_END, "(Line 2) Expected xml start, got '<?xml'");
	fetch_notif_error();
	init_xml1(NOTIF_DT "\n" NOTIF_DT "\n" NOTIF_END, "(Line 2) Expected xml start, got '<!DOCTYPE'");
	fetch_notif_error();
}
END_TEST

/*
 * next_tkn() will never parse an attribute value.
 * Attribute values are done by a separate function; next_quoted().
 * This is handy, because attribute values only ever happen in tkn3.
 * Attribute values are the only kind of backupable tokens that might exceed
 * MAX_NAME_SIZE bytes.
 * This means tkn1 and tkn2 could be micro-optimized to contain smaller backup
 * buffers.
 * Which is not something I'm going to bother with right now, but I'm leaving
 * this test in case I forget why I'm keeping attribute value parsing out of
 * next_tkn().
 */
START_TEST(notif_misplaced_attribute)
{
	init_xml1(
		"<notification \"12345678901234567890\"=\"" XMLNS "\" version=\"1\" session_id=\"abcd\" serial=\"13\">\n"
			SNAPSHOT("https://a/s.xml", HASH) "\n"
		NOTIF_END,
		"(Line 1) Unexpected character: '\"'"
	);
	fetch_notif_error();
}
END_TEST

START_TEST(snapshot_base64)
{
	init_xml1(
		"<snapshot xmlns=\"" XMLNS "\" version=\"1\" session_id=\"abcd\" serial=\"12\">"
			"<publish uri=\"rsync://a/mod/c.cer\">ZXhhbXBsZTE=</publish>"
			"<publish uri=\"rsync://a/mod/m.mft\">ZXhhbXBsZTI=</publish>"
			"<publish uri=\"rsync://a/mod/c.crl\">ZXhhbXBsZTM=</publish>"
		"</snapshot>",
		NULL
	);

	explode_snapshot("5d1915d207dc35cf2e595daa014217698d241cc877ba0558ea3d7aa2472f9d54");

	ck_file("example1", "tmp/rrdp/C");
	ck_file("example2", "tmp/rrdp/D");
	ck_file("example3", "tmp/rrdp/E");
}
END_TEST

START_TEST(snapshot_base64_newlines)
{
	init_xml1(
		"<snapshot xmlns=\"" XMLNS "\" version=\"1\" session_id=\"abcd\" serial=\"12\">\n"
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
		"<snapshot xmlns=\"" XMLNS "\" version=\"1\" session_id=\"abcd\" serial=\"12\">\n"
			"<publish uri=\"rsync://a/b/c.cer\">\n"
				"ZXhhbXBsZTE=\n"
			"</publish>\n"
			"<withdraw uri=\"rsync://a/b/d.mft\" hash=\"" HASH "\"/>\n"
			"<publish uri=\"rsync://a/b/e.crl\">ZXhhbXBsZTM=</publish>\n"
		"</snapshot>",
		"(Line 5) Unexpected token: withdraw"
	);
	explode_snapshot_error("");
}
END_TEST

START_TEST(snapshot_bad_data_types)
{
	init_xml1(
		"<snapshot xmlns=\"" XMLNS "\" version=\"1\" session_id=\"abcd\" serial=\"12\">\n"
			"<publish uri=\"rsync://a/b/c.cer\">ZXh^hbXBsZTE=</publish>\n"
		"</snapshot>",
		"(Line 2) Unrecognized base64 char: ^"
	);
	explode_snapshot_error("");
}
END_TEST

START_TEST(snapshot_base64_newline_counting)
{
	init_xml1(
		"<snapshot xmlns=\"" XMLNS "\" version=\"1\" session_id=\"abcd\" serial=\"12\">\n"
			"<publish\n"
			    "uri\n"
			    "=\n"
			    "\"rsync://a/b/c.cer\">\n"
				"ZXh\n"
				"hbX\n"
				"<!--\n"
					"comment line 1\n"
					"comment line 2\n"
				"-->\n"
				"BsZ\n"
				"T*E=\n"
			"</publish>\n"
		"</snapshot>",
		"(Line 13) Unrecognized base64 char: *"
	);
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
	__URI_INIT(&url, NOTIF_URL);
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
		"<delta xmlns=\"" XMLNS "\" version=\"1\" session_id=\"abcd\" serial=\"10\">"
			"<publish uri=\"rsync://a/mod/c.cer\">ZXhhbXBsZTE=</publish>"
		"</delta>",
		NULL
	);
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
	tcase_add_test(xml, notif_mandatory_whitespace);
	tcase_add_test(xml, notif_comments);
	tcase_add_test(xml, notif_unterminated_comment);
	tcase_add_test(xml, notif_comment_boundaries);
	tcase_add_test(xml, notif_lacks_snapshot);
	tcase_add_test(xml, notif_not_ascii);
	tcase_add_test(xml, notif_buffer_interruptions);
	tcase_add_test(xml, notif_massive_whitespace);
	tcase_add_test(xml, notif_drip_feed_whitespace);
	tcase_add_test(xml, notif_micro_drip_feed);
	tcase_add_test(xml, notif_long_token);
	tcase_add_test(xml, notif_long_url);
	tcase_add_test(xml, notif_long_serial);
	tcase_add_test(xml, notif_long_delta_serial);
	tcase_add_test(xml, notif_sort_deltas);
	tcase_add_test(xml, notif_bad_deltas);
	tcase_add_test(xml, notif_bad_data_types);
	tcase_add_test(xml, notif_xml_hdrs);
	tcase_add_test(xml, notif_pi_boundaries);
	tcase_add_test(xml, notif_pi_rejected);
	tcase_add_test(xml, notif_not_rrdp);
	tcase_add_test(xml, notif_misplaced_attribute);
	tcase_add_test(xml, snapshot_base64);
	tcase_add_test(xml, snapshot_base64_newlines);
	tcase_add_test(xml, snapshot_withdraw);
	tcase_add_test(xml, snapshot_bad_data_types);
	tcase_add_test(xml, snapshot_base64_newline_counting);
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
