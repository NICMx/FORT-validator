#include <errno.h>
#include <check.h>

#include "alloc.c"
#include "cachent.c"
#include "common.c"
#include "mock.c"
#include "object/manifest.c"
#include "types/map.c"
#include "types/path.c"
#include "types/url.c"

MOCK_ABORT_INT(signed_object_decode, struct signed_object *sobj, char const *path)
MOCK_ABORT_VOID(signed_object_cleanup, struct signed_object *sobj)
MOCK_VOID(__delete_node_cb, struct cache_node const *node)

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

static Suite *
mft_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("core");
	tcase_add_test(core, check_validate_current_directory);

	suite = suite_create("mft");
	suite_add_tcase(suite, core);
	return suite;
}

int
main(int argc, char **argv)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = mft_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
