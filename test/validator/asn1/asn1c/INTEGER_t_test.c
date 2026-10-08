#include <check.h>

#include "alloc.c"
#include "common.c"
#include "asn1/asn1c/asn_codecs_prim.c"
#include "asn1/asn1c/INTEGER.c"
#include "mock.c"

__MOCK_ABORT(asn__format_to_callback, ssize_t, 0,
    int (*cb)(const void *, size_t, void *key), void *key, const char *fmt, ...)
MOCK_ABORT_INT(asn_generic_no_constraint,
    const asn_TYPE_descriptor_t *td, const void *ptr,
    asn_app_constraint_failed_f *cb, void *key)
static asn_dec_rval_t dummy;
__MOCK_ABORT(ber_check_tags, asn_dec_rval_t, dummy,
    const asn_codec_ctx_t *opt_codec_ctx, const asn_TYPE_descriptor_t *td,
    asn_struct_ctx_t *opt_ctx, const void *ptr, size_t size, int tag_mode,
    int last_tag_form, ber_tlv_len_t *last_length, int *opt_tlv_form)
__MOCK_ABORT(der_write_tags, ssize_t, 0,
    const asn_TYPE_descriptor_t *sd, size_t struct_length, int tag_mode,
    int last_tag_form, ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb,
    void *app_key)
__MOCK_ABORT(json_int_new, json_t *, NULL, json_int_t value)

START_TEST(test_serde)
{
	INTEGER_t bi;
	char *str;

	ck_assert_int_eq(0, asn_str2INTEGER(NULL, &bi));
	ck_assert_ptr_eq(NULL, bi.buf);
	ck_assert_int_eq(0, bi.size);
	ck_assert_ptr_eq(NULL, asn_INTEGER2str(NULL));

	ck_assert_int_eq(EINVAL, asn_str2INTEGER("", &bi));
	ck_assert_int_eq(EINVAL, asn_str2INTEGER("a", &bi));
	ck_assert_int_eq(EINVAL, asn_str2INTEGER("abc", &bi));

	ck_assert_int_eq(0, asn_str2INTEGER("ab", &bi));
	ck_assert_int_eq(1, bi.size);
	ck_assert_int_eq(0xAB, bi.buf[0]);
	str = asn_INTEGER2str(&bi);
	ck_assert_str_eq("AB", str);
	INTEGER_cleanup(&bi);
	free(str);

	ck_assert_int_eq(0, asn_str2INTEGER("abc5", &bi));
	ck_assert_int_eq(2, bi.size);
	ck_assert_int_eq(0xAB, bi.buf[0]);
	ck_assert_int_eq(0xC5, bi.buf[1]);
	str = asn_INTEGER2str(&bi);
	ck_assert_str_eq("ABC5", str);
	INTEGER_cleanup(&bi);
	free(str);

	ck_assert_int_eq(EINVAL, asn_str2INTEGER("abc59", &bi));

	ck_assert_int_eq(0, asn_str2INTEGER("abcdef0123456789ABCDEFabcdef012345678901", &bi));
	ck_assert_int_eq(20, bi.size);
	ck_assert_int_eq(0xAB, bi.buf[0]);
	ck_assert_int_eq(0xCD, bi.buf[1]);
	ck_assert_int_eq(0x89, bi.buf[18]);
	ck_assert_int_eq(0x01, bi.buf[19]);
	str = asn_INTEGER2str(&bi);
	ck_assert_str_eq("ABCDEF0123456789ABCDEFABCDEF012345678901", str);
	INTEGER_cleanup(&bi);
	free(str);

	ck_assert_int_eq(EOVERFLOW, asn_str2INTEGER("abcdef0123456789ABCDEFabcdef0123456789012", &bi));
	ck_assert_int_eq(EOVERFLOW, asn_str2INTEGER("abcdef0123456789ABCDEFabcdef0123456789013", &bi));
	ck_assert_int_eq(EINVAL, asn_str2INTEGER("z", &bi));
	ck_assert_int_eq(EINVAL, asn_str2INTEGER("abmd", &bi));
}
END_TEST

static Suite *create_suite(void)
{
	Suite *suite;
	TCase *serde;

	serde = tcase_create("serde");
	tcase_add_test(serde, test_serde);

	suite = suite_create("INTEGER_t");
	suite_add_tcase(suite, serde);

	return suite;
}

int main(void)
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
