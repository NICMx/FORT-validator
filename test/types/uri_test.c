#include <check.h>
#include <errno.h>
#include <stdint.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "types/uri.c"
#include "data_structure/path_builder.c"

/* Mocks */

struct rpki_uri *notification;

MOCK(state_retrieve, struct validation *, NULL, void)
MOCK(validation_get_notification_uri, struct rpki_uri *, notification,
    struct validation *state)

/* Tests */

START_TEST(test_constructor)
{
	struct rpki_uri *uri;

	ck_assert_int_eq(ENOTHTTPS, uri_create(&uri, UT_HTTPS, ""));
	ck_assert_int_eq(ENOTHTTPS, uri_create(&uri, UT_HTTPS, "h"));
	ck_assert_int_eq(ENOTHTTPS, uri_create(&uri, UT_HTTPS, "http"));
	ck_assert_int_eq(ENOTHTTPS, uri_create(&uri, UT_HTTPS, "https"));
	ck_assert_int_eq(ENOTHTTPS, uri_create(&uri, UT_HTTPS, "https:"));
	ck_assert_int_eq(ENOTHTTPS, uri_create(&uri, UT_HTTPS, "https:/"));
	ck_assert_int_eq(-EINVAL, uri_create(&uri, UT_HTTPS, "https://"));

	ck_assert_int_eq(0, uri_create(&uri, UT_HTTPS, "https://a.b.c"));
	ck_assert_str_eq("https://a.b.c", uri_get_global(uri));
	ck_assert_str_eq("https/a.b.c", uri_get_local(uri));
	uri_refput(uri);

	ck_assert_int_eq(0, uri_create(&uri, UT_HTTPS, "https://a.b.c/"));
	ck_assert_str_eq("https://a.b.c/", uri_get_global(uri));
	ck_assert_str_eq("https/a.b.c", uri_get_local(uri));
	uri_refput(uri);

	ck_assert_int_eq(0, uri_create(&uri, UT_HTTPS, "https://a.b.c/d"));
	ck_assert_str_eq("https://a.b.c/d", uri_get_global(uri));
	ck_assert_str_eq("https/a.b.c/d", uri_get_local(uri));
	uri_refput(uri);

	ck_assert_int_eq(0, uri_create(&uri, UT_HTTPS, "https://a.b.c/d/e"));
	ck_assert_str_eq("https://a.b.c/d/e", uri_get_global(uri));
	ck_assert_str_eq("https/a.b.c/d/e", uri_get_local(uri));
	uri_refput(uri);

	ck_assert_int_eq(0, uri_create(&uri, UT_HTTPS, "https://a.b.c/d/.."));
	ck_assert_str_eq("https://a.b.c/d/..", uri_get_global(uri));
	ck_assert_str_eq("https/a.b.c", uri_get_local(uri));
	uri_refput(uri);

	ck_assert_int_eq(0, uri_create(&uri, UT_HTTPS, "https://a.b.c/."));
	ck_assert_str_eq("https://a.b.c/.", uri_get_global(uri));
	ck_assert_str_eq("https/a.b.c", uri_get_local(uri));
	uri_refput(uri);

	ck_assert_int_eq(0, uri_create(&uri, UT_HTTPS, "https://a.b.c/././d/././e/./."));
	ck_assert_str_eq("https://a.b.c/././d/././e/./.", uri_get_global(uri));
	ck_assert_str_eq("https/a.b.c/d/e", uri_get_local(uri));
	uri_refput(uri);

	ck_assert_int_eq(0, uri_create(&uri, UT_HTTPS, "https://a.b.c/a/b/.././.."));
	ck_assert_str_eq("https://a.b.c/a/b/.././..", uri_get_global(uri));
	ck_assert_str_eq("https/a.b.c", uri_get_local(uri));
	uri_refput(uri);

	ck_assert_int_eq(-EINVAL, uri_create(&uri, UT_HTTPS, "https://a.b.c/.."));
	ck_assert_int_eq(-EINVAL, uri_create(&uri, UT_HTTPS, "https://a.b.c/../.."));
	ck_assert_int_eq(-EINVAL, uri_create(&uri, UT_HTTPS, "https://a.b.c/d/../.."));
	ck_assert_int_eq(-EINVAL, uri_create(&uri, UT_HTTPS, "https://a.b.c/d/../../.."));
	ck_assert_int_eq(-EINVAL, uri_create(&uri, UT_HTTPS, "https://."));
	ck_assert_int_eq(-EINVAL, uri_create(&uri, UT_HTTPS, "https://./."));
	ck_assert_int_eq(-EINVAL, uri_create(&uri, UT_HTTPS, "https://.."));
	ck_assert_int_eq(-EINVAL, uri_create(&uri, UT_HTTPS, "https://../.."));
	ck_assert_int_eq(-EINVAL, uri_create(&uri, UT_HTTPS, "https://../../.."));

	ck_assert_int_eq(ENOTHTTPS, uri_create(&uri, UT_HTTPS, "rsync://a.b.c/d"));
	ck_assert_int_eq(ENOTHTTPS, uri_create(&uri, UT_HTTPS, "http://a.b.c/d"));
	ck_assert_int_eq(ENOTRSYNC, uri_create(&uri, UT_RSYNC, "https://a.b.c/d"));
}
END_TEST

#define BUFFER_LEN 128
static uint8_t buffer[BUFFER_LEN];

static int
__test_validate(char const *src, size_t len)
{
	IA5String_t dst;
	unsigned int i;

	memcpy(buffer, src, len);
	for (i = len; i < BUFFER_LEN - 1; i++)
		buffer[i] = '_';
	buffer[BUFFER_LEN - 1] = 0;

	dst.buf = buffer;
	dst.size = len;

	return validate_mft_file(&dst);
}

#define test_validate(str) __test_validate(str, sizeof(str) - 1)

START_TEST(check_validate_current_directory)
{
	ck_assert_int_eq(-EINVAL, test_validate(""));
	ck_assert_int_eq(-EINVAL, test_validate("."));
	ck_assert_int_eq(-EINVAL, test_validate(".."));

	ck_assert_int_eq(-EINVAL, test_validate("filename"));
	ck_assert_int_eq(-EINVAL, test_validate("filename."));
	ck_assert_int_eq(-EINVAL, test_validate("filename.a"));
	ck_assert_int_eq(-EINVAL, test_validate("filename.ab"));
	ck_assert_int_eq(0, test_validate("filename.abc"));
	ck_assert_int_eq(-EINVAL, test_validate("file.abcd"));

	ck_assert_int_eq(0, test_validate("file-name.ABC"));
	ck_assert_int_eq(0, test_validate("file_name.123"));
	ck_assert_int_eq(0, test_validate("file0name.aB2"));
	ck_assert_int_eq(0, test_validate("file9name.---"));
	ck_assert_int_eq(0, test_validate("FileName.A3_"));
	ck_assert_int_eq(-EINVAL, test_validate("file.name.abc"));
	ck_assert_int_eq(-EINVAL, test_validate("file/name.abc"));
	ck_assert_int_eq(-EINVAL, test_validate("file\0name.abc"));
	ck_assert_int_eq(-EINVAL, test_validate("filename.abc\0filename.abc"));
	ck_assert_int_eq(-EINVAL, test_validate("filenameabc\0filename.abc"));
	ck_assert_int_eq(0, test_validate("-.---"));

	ck_assert_int_eq(0, test_validate("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890-_.-_-"));
	ck_assert_int_eq(0, test_validate("vixxBTS_TVXQ-2pmGOT7.cer"));
}
END_TEST

START_TEST(check_caged)
{
	struct rpki_uri *uri;

	ck_assert_int_eq(0, uri_create(&notification, UT_HTTPS, "https://a.b.c/d/e.xml"));
	ck_assert_int_eq(0, uri_create(&uri, UT_CAGED, "rsync://x.y.z/v/w.cer"));
	ck_assert_str_eq("rrdp/a.b.c/d/e.xml/x.y.z/v/w.cer", uri_get_local(uri));
	uri_refput(uri);
	uri_refput(notification);

	ck_assert_int_eq(0, uri_create(&notification, UT_HTTPS, "https://a.b.c"));
	ck_assert_int_eq(0, uri_create(&uri, UT_CAGED, "rsync://w"));
	ck_assert_str_eq("rrdp/a.b.c/w", uri_get_local(uri));
	uri_refput(uri);
	uri_refput(notification);
}
END_TEST

Suite *address_load_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, test_constructor);
	tcase_add_test(core, check_validate_current_directory);
	tcase_add_test(core, check_caged);

	suite = suite_create("Encoding checking");
	suite_add_tcase(suite, core);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = address_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
