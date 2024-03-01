#include <check.h>
#include <stdlib.h>

#include "alloc.c"
#include "common.c"
#include "file.c"
#include "mock.c"
#include "data_structure/path_builder.c"
#include "types/uri.c"
#include "crypto/hash.c"

MOCK_ABORT_INT(cache_tmpfile, char **filename)

/* Actually mostly tests libcrypto's sanity, not Fort's. */
START_TEST(test_hash)
{
	static unsigned char FORT_SHA1[] = {
		0xe5, 0x79, 0x65, 0xf7, 0x36, 0xd2, 0x9d, 0x43, 0xde, 0x05,
		0xf7, 0x02, 0x86, 0xa7, 0xf4, 0xcc, 0x5b, 0x74, 0x8c, 0xa7
	};
	static unsigned char FORT_SHA256[] = {
		0xb6, 0x9f, 0xee, 0xa9, 0xef, 0xa8, 0x61, 0x5c, 0xd4, 0x91,
		0x95, 0x7b, 0x7e, 0xf8, 0x28, 0xef, 0xb4, 0x10, 0xc2, 0xdd,
		0x67, 0x6c, 0xa0, 0x63, 0x75, 0x9a, 0x68, 0x9a, 0xf4, 0xfe,
		0xf9, 0xb1
	};

	static unsigned char FILE_SHA1[] = {
		0xea, 0x3c, 0xa1, 0xc6, 0xe2, 0x3a, 0x70, 0x1a, 0xe8, 0x97,
		0xec, 0x0b, 0xf0, 0xa2, 0x20, 0x66, 0xe1, 0xf8, 0x8b, 0xb5
	};

	static unsigned char FILE_SHA256[] = {
		0x00, 0xb8, 0x08, 0xa1, 0x60, 0x5e, 0x13, 0xfe, 0xb6, 0xc5,
		0x71, 0x67, 0x1f, 0xb2, 0x29, 0x2b, 0xa8, 0x7f, 0x0f, 0x28,
		0xed, 0xe3, 0xe0, 0xe3, 0x51, 0xfe, 0xd8, 0xf5, 0x7c, 0xad,
		0x68, 0x06
	};

	struct hash_algorithm const *ha;
	char const *name;
	char const *input = "Fort";
	struct rpki_uri uri = { 0 };

	hash_setup();

	uri.global = "https://example.com/resources/lorem-ipsum.txt";
	uri.global_len = strlen(uri.global);
	uri.local = "resources/lorem-ipsum.txt";
	uri.type = UT_TA_HTTP;
	uri.references = 1;

	ha = hash_get_sha1();
	ck_assert_uint_eq(20, hash_get_size(ha));
	name = hash_get_name(ha);
	ck_assert(strcasecmp("sha1", name) || strcasecmp("sha-1", name));

	ck_assert_int_eq(0, hash_validate(ha, (unsigned char *)input, strlen(input), FORT_SHA1, sizeof(FORT_SHA1)));
	ck_assert_int_eq(EINVAL, hash_validate(ha, (unsigned char *)input, strlen(input), FORT_SHA1, sizeof(FORT_SHA1) - 1));
	FORT_SHA1[1] = 1;
	ck_assert_int_eq(EINVAL, hash_validate(ha, (unsigned char *)input, strlen(input), FORT_SHA1, sizeof(FORT_SHA1)));

	ck_assert_int_eq(0, hash_validate_file(ha, &uri, FILE_SHA1, sizeof(FILE_SHA1)));
	ck_assert_int_eq(-EINVAL, hash_validate_file(ha, &uri, FILE_SHA1, sizeof(FILE_SHA1) - 10));
	FILE_SHA1[19] = 0;
	ck_assert_int_eq(-EINVAL, hash_validate_file(ha, &uri, FILE_SHA1, sizeof(FILE_SHA1)));

	ha = hash_get_sha256();
	ck_assert_uint_eq(32, hash_get_size(ha));
	name = hash_get_name(ha);
	ck_assert(strcasecmp("sha256", name) || strcasecmp("sha-256", name));

	ck_assert_int_eq(0, hash_validate(ha, (unsigned char *)input, strlen(input), FORT_SHA256, sizeof(FORT_SHA256)));
	ck_assert_int_eq(EINVAL, hash_validate(ha, (unsigned char *)input, strlen(input), FORT_SHA256, sizeof(FORT_SHA256) - 6));
	FORT_SHA256[10] = 0;
	ck_assert_int_eq(EINVAL, hash_validate(ha, (unsigned char *)input, strlen(input), FORT_SHA256, sizeof(FORT_SHA256)));

	ck_assert_int_eq(0, hash_validate_file(ha, &uri, FILE_SHA256, sizeof(FILE_SHA256)));
	ck_assert_int_eq(-EINVAL, hash_validate_file(ha, &uri, FILE_SHA256, sizeof(FILE_SHA256) - 1));
	FILE_SHA256[31] = 10;
	ck_assert_int_eq(-EINVAL, hash_validate_file(ha, &uri, FILE_SHA256, sizeof(FILE_SHA256)));

	hash_teardown();
}
END_TEST

static Suite *
pdu_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("hash");
	tcase_add_test(core, test_hash);

	suite = suite_create("hash");
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
