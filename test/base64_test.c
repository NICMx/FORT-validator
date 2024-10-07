#include <check.h>

#include "alloc.c"
#include "base64.c"
#include "common.h"
#include "mock.c"
#include "types/array.h"

static void
ck_uchar_array(unsigned char *expected, size_t expected_len,
    unsigned char *actual, size_t actual_len)
{
	size_t i;
	ck_assert_uint_eq(expected_len, actual_len);
	for (i = 0; i < expected_len; i++)
		ck_assert_uint_eq(expected[i], actual[i]);
}


static void
ck_char_array(char *expected, unsigned char *actual, size_t actual_len)
{
	ck_uchar_array((unsigned char *)expected, strlen(expected), actual,
	    actual_len);
}

START_TEST(test_base64_decode)
{
	static char *fort = "Fort";
	static char *potato = "potato";
	static unsigned char emojis[] = { 0xf0, 0x9f, 0x98, 0x80, 0xf0, 0x9f, 0xab, 0xa0 };
	static char *lorem_ipsum = "Lorem ipsum dolor sit amet, consectetur "
	    "adipiscing elit. In a malesuada neque. Nunc efficitur at leo ac "
	    "feugiat. Aliquam velit erat, molestie nec nulla vitae, accumsan "
	    "accumsan ipsum. Nunc mattis quam sit amet turpis sollicitudin "
	    "fringilla. Sed id ante finibus, finibus erat in, vestibulum "
	    "lectus. Aenean sed massa ut lacus efficitur sollicitudin. Mauris "
	    "at imperdiet augue. Maecenas tempus ornare odio, egestas faucibus "
	    "ante commodo id. Morbi at urna nisl. Phasellus gravida felis non "
	    "erat ornare, at mattis magna venenatis. In ac lorem vel est "
	    "euismod finibus. Nam mauris felis, laoreet id eros sed, suscipit "
	    "gravida justo. In a dictum erat. Pellentesque habitant morbi "
	    "tristique senectus et netus et malesuada fames ac turpis egestas.";
	unsigned char *dec;
	size_t declen;

	/* Empty */
	ck_assert_int_eq(true, base64_decode("", 0, &dec, &declen));
	ck_assert_uint_eq(0, declen);
	free(dec);

	/* With padding */
	ck_assert_int_eq(true, base64_decode("Rm9ydA==", 0, &dec, &declen));
	ck_char_array(fort, dec, declen);
	free(dec);

	/* No padding */
	ck_assert_int_eq(true, base64_decode("cG90YXRv", 0, &dec, &declen));
	ck_char_array(potato, dec, declen);
	free(dec);

	/* Not ASCII */
	ck_assert_int_eq(true, base64_decode("8J+YgPCfq6A=", 0, &dec, &declen));
	ck_uchar_array(emojis, ARRAY_LEN(emojis), dec, declen);
	free(dec);

	/* Illegal character */
	ck_assert_int_eq(false, base64_decode("R!m9ydA=", 0, &dec, &declen));
	/* Length not multiple of 4 */
	ck_assert_int_eq(false, base64_decode("Rm9ydA=", 0, &dec, &declen));

	/* Long, no whitespace */
	ck_assert_int_eq(true, base64_decode("TG9yZW0gaXBzdW0gZG9sb3Igc2l0I"
	    "GFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gSW4gYSBtYWxlc"
	    "3VhZGEgbmVxdWUuIE51bmMgZWZmaWNpdHVyIGF0IGxlbyBhYyBmZXVnaWF0L"
	    "iBBbGlxdWFtIHZlbGl0IGVyYXQsIG1vbGVzdGllIG5lYyBudWxsYSB2aX"
	    "RhZSwgYWNjdW1zYW4gYWNjdW1zYW4gaXBzdW0uIE51bmMgbWF0dGlzIHF1YW0gc2"
	    "l0IGFtZXQgdHVycGlzIHNvbGxpY2l0dWRpbiBmcmluZ2lsbGEuIFNlZCBpZCBhbn"
	    "RlIGZpbmlidXMsIGZpbmlidXMgZXJhdCBpbiwgdmVzdGlidWx1bSBsZWN0dXMuIE"
	    "FlbmVhbiBzZWQgbWFzc2EgdXQgbGFjdXMgZWZmaWNpdHVyIHNvbGxpY2l0dWRpbi"
	    "4gTWF1cmlzIGF0IGltcGVyZGlldCBhdWd1ZS4gTWFlY2VuYXMgdGVtcHVzIG9ybm"
	    "FyZSBvZGlvLCBlZ2VzdGFzIGZhdWNpYnVzIGFudGUgY29tbW9kbyBpZC4gTW9yYm"
	    "kgYXQgdXJuYSBuaXNsLiBQaGFzZWxsdXMgZ3JhdmlkYSBmZWxpcyBub24gZXJhdC"
	    "Bvcm5hcmUsIGF0IG1hdHRpcyBtYWduYSB2ZW5lbmF0aXMuIEluIGFjIGxvcmVtIH"
	    "ZlbCBlc3QgZXVpc21vZCBmaW5pYnVzLiBOYW0gbWF1cmlzIGZlbGlzLCBsYW9yZW"
	    "V0IGlkIGVyb3Mgc2VkLCBzdXNjaXBpdCBncmF2aWRhIGp1c3RvLiBJbiBhIGRpY3"
	    "R1bSBlcmF0LiBQZWxsZW50ZXNxdWUgaGFiaXRhbnQgbW9yYmkgdHJpc3RpcXVlIH"
	    "NlbmVjdHVzIGV0IG5ldHVzIGV0IG1hbGVzdWFkYSBmYW1lcyBhYyB0dXJwaXMgZW"
	    "dlc3Rhcy4=", 0, &dec, &declen));
	ck_char_array(lorem_ipsum, dec, declen);
	free(dec);

	/* Long, whitespace */
	ck_assert_int_eq(true, base64_decode("  TG9yZW0gaXBzdW0gZG9sb3Igc2l0I\n"
	    "    GFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gSW4gYSBtYWxlc\n"
	    "3VhZGEgbmVxdWUuIE51bmMgZWZmaWNpdHVyIGF0IGxlbyBhYyBmZXVnaWF0L\n\n\n"
	    "iBBbGlxdWFtIHZlbGl0I	GVyYXQsIG1vbGVzdGllIG5lYyBudWxsYSB2aX\n"
	    "RhZSwgYWNjdW1zYW4gYWNjdW1zYW4gaXBzdW0uIE51bmMgbWF0dGlzIHF1YW0gc2\n"
	    "l0IGFtZXQgdHVycGlzIHNvbGxpY2l0dWRpbiBmcmluZ2lsbGEuIFNlZCBpZCBhbn\n"
	    "RlIGZpbmlidXMsIGZpbmlidXMgZXJhdCBpbiwgdmVzdGlidWx1bSBsZWN0dXMuIE\n"
	    "FlbmVhbiBzZWQgbWFzc2EgdXQgbGFjdXMgZWZmaWNpdHVyIHNvbGxpY2l0dWRpbi\n"
	    "4gTWF1cmlzIGF0IGltcGVyZGlldCBhdWd1ZS4gTWFlY2VuYXMgdGVtcHVzIG9ybm\n"
	    "FyZSBvZGlvLCBlZ2VzdGFzIGZhdWNpYnVzIGFudGUgY29tbW9kbyBpZC4gTW9yYm\n"
	    "kgYXQgdXJuYSBuaXNsLiBQaGFzZWxsdXMgZ3JhdmlkYSBmZWxpcyBub24gZXJhdC\n"
	    "Bvcm5hcmUsIGF0IG1hdHRpcyBtYWduYSB2ZW5lbmF0aXMuIEluIGFjIGxvcmVtIH\n"
	    "ZlbCBlc3QgZXVpc21vZCBmaW5pYnVzLiBOYW0gbWF1cmlzIGZlbGlzLCBsYW9yZW\n"
	    "V0IGlkIGVyb3Mgc2VkLCBzdXNjaXBpdCBncmF2aWRhIGp1c3RvLiBJbiBhIGRpY3\n"
	    "R1bSBlcmF0LiBQZWxsZW50ZXNxdWUgaGFiaXRhbnQgbW9yYmkgdHJpc3RpcXVlIH\n"
	    "NlbmVjdHVzIGV0IG5ldHVzIGV0IG1hbGVzdWFkYSBmYW1lcyBhYyB0dXJwaXMgZW\n"
	    "dlc3Rhcy4=\n\n\n", 0, &dec, &declen));
	ck_char_array(lorem_ipsum, dec, declen);
	free(dec);
}
END_TEST

static Suite *
pdu_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("core");
	tcase_add_test(core, test_base64_decode);

	suite = suite_create("base64");
	suite_add_tcase(suite, core);
	return suite;
}

int
main(int argc, char **argv)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = pdu_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
