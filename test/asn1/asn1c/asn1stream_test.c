#include <check.h>

#include "alloc.c"
#include "mock.c"
#include "asn1/asn1c/ber_decoder.c"
#include "asn1/asn1c/ber_tlv_length.c"
#include "asn1/asn1c/ber_tlv_tag.c"
#include "asn1/asn1c/constr_CHOICE.c"
#include "asn1/asn1c/constr_SEQUENCE.c"
#include "asn1/asn1c/constr_TYPE.c"
#include "asn1/asn1c/constraints.c"
#include "asn1/asn1c/der_encoder.c"
#include "asn1/asn1c/OCTET_STRING.c"
#include "asn1/asn1c/OPEN_TYPE.c"
#include "asn1/asn1c/RsyncRequest.c"

MOCK_ABORT_PTR(json_strn_new, json_t, const char *value, size_t len)
MOCK_ABORT_PTR(json_obj_new, json_t, void)
MOCK_ABORT_PTR(json_null, json_t, void)
MOCK_UINT(config_get_asn1_decode_max_stack, 16 * 1024, void)

START_TEST(test_multiple)
{
	struct RsyncRequest src = { 0 };
	struct RsyncRequest *dst = NULL;
	unsigned char buf[64] = { 0 };
	asn_enc_rval_t encres;
	asn_dec_rval_t decres;

	ck_assert_int_eq(0, OCTET_STRING_fromString(&src.url, "url"));
	ck_assert_int_eq(0, OCTET_STRING_fromString(&src.path, "path"));
	encres = der_encode_to_buffer(&asn_DEF_RsyncRequest, &src, buf, sizeof(buf));
	ck_assert_int_eq(13, encres.encoded);

	ck_assert_int_eq(0, OCTET_STRING_fromString(&src.url, "https://a.b.c/d/e.cer"));
	ck_assert_int_eq(0, OCTET_STRING_fromString(&src.path, "tmp/http/a.b.c/d/e.cer"));
	encres = der_encode_to_buffer(&asn_DEF_RsyncRequest, &src, buf + 13, sizeof(buf) - 13);
	ck_assert_int_eq(49, encres.encoded);

	decres = ber_decode(&asn_DEF_RsyncRequest, (void **)&dst, buf, sizeof(buf));
	ck_assert_int_eq(RC_OK, decres.code);
	ck_assert_int_eq(13, decres.consumed);
	ck_assert_uint_eq(3, dst->url.size);
	ck_assert_mem_eq("url", dst->url.buf, 3);
	ck_assert_uint_eq(4, dst->path.size);
	ck_assert_mem_eq("path", dst->path.buf, 4);

	dst = NULL;

	/* Fragment */
	decres = ber_decode(&asn_DEF_RsyncRequest, (void **)&dst, buf + 13, 13);
	ck_assert_int_eq(RC_WMORE, decres.code);
	ck_assert_int_eq(13, decres.consumed);
	ck_assert_ptr_ne(NULL, dst);

	decres = ber_decode(&asn_DEF_RsyncRequest, (void **)&dst, buf + 26, sizeof(buf) - 26);
	ck_assert_int_eq(RC_OK, decres.code);
	ck_assert_int_eq(36, decres.consumed);
	ck_assert_uint_eq(21, dst->url.size);
	ck_assert_mem_eq("https://a.b.c/d/e.cer", dst->url.buf, 21);
	ck_assert_uint_eq(22, dst->path.size);
	ck_assert_mem_eq("tmp/http/a.b.c/d/e.cer", dst->path.buf, 22);
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *pipes;

	pipes = tcase_create("multiple");
	tcase_add_test(pipes, test_multiple);

	suite = suite_create("asn1 stream");
	suite_add_tcase(suite, pipes);

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
