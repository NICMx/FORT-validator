#include <check.h>

#include "alloc.c"
#include "mock.c"
#include "object/vcard.c"

#define VC_BEGIN	"BEGIN:VCARD\r\n"
#define VC_VERSION	"VERSION:4.0\r\n"
#define VC_FN		"FN:name\r\n"
#define VC_ORG		"ORG:organization\r\n"
#define VC_ADR		"ADR;address\r\n"
#define VC_TEL		"TEL;12345678\r\n"
#define VC_EMAIL	"EMAIL:e@ma.il\r\n"
#define VC_END		"END:VCARD\r\n"

#define INIT_STR8(name, str) do {					\
	printf("- %s:\n", name);					\
	str8.buf = (uint8_t *) (str);					\
	str8.size = strlen(str);					\
} while (0)

START_TEST(vcard_normal)
{
	OCTET_STRING_t str8;

	INIT_STR8(
	    "Minimal",
	    VC_BEGIN VC_VERSION VC_FN VC_ORG VC_END
	);
	ck_assert_int_eq(0, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "Full",
	    VC_BEGIN VC_VERSION VC_FN VC_ORG VC_ADR VC_TEL VC_EMAIL VC_END
	);
	ck_assert_int_eq(0, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "Missing locator",
	    VC_BEGIN VC_VERSION VC_FN VC_END
	);
	ck_assert_int_eq(-EINVAL, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "Missing name",
	    VC_BEGIN VC_VERSION VC_ORG VC_END
	);
	ck_assert_int_eq(-EINVAL, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "Unknown property",
	    VC_BEGIN VC_VERSION VC_FN VC_ORG "POTATO:potato\r\n" VC_END
	);
	ck_assert_int_eq(-EINVAL, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "No newline",
	    VC_BEGIN VC_VERSION "FN:name" VC_ORG VC_END
	);
	ck_assert_int_eq(-EINVAL, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "\\r newline",
	    VC_BEGIN VC_VERSION "FN:name\r" VC_ORG VC_END
	);
	ck_assert_int_eq(-EINVAL, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "\\n newline",
	    VC_BEGIN VC_VERSION "FN:name\n" VC_ORG VC_END
	);
	ck_assert_int_eq(-EINVAL, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "Last line has no valid newline",
	    VC_BEGIN VC_VERSION VC_FN VC_ORG "END:VCARD"
	);
	ck_assert_int_eq(-EINVAL, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "Stray null character (in non-constant)",
	    VC_BEGIN VC_VERSION "FN:n\0ame\r\n" VC_ORG VC_END
	);
	str8.size += strlen(" ame\r\n" VC_ORG VC_END);
	ck_assert_int_eq(0, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "Stray null character (in constant)",
	    VC_BEGIN "VERSION:4.\00\r\n" VC_FN VC_ORG VC_END
	);
	str8.size += strlen(" 0\r\n" VC_FN VC_ORG VC_END);
	ck_assert_int_eq(-EINVAL, handle_ghostbusters_vcard(&str8));

	INIT_STR8(
	    "Garbage after END",
	    VC_BEGIN VC_VERSION VC_FN VC_ORG VC_END VC_EMAIL
	);
	ck_assert_int_eq(-EINVAL, handle_ghostbusters_vcard(&str8));
}
END_TEST

static Suite *create_suite(void)
{
	Suite *suite;
	TCase *hgv;

	hgv = tcase_create("handle_ghostbusters_vcard()");
	tcase_add_test(hgv, vcard_normal);

	suite = suite_create("vCard");
	suite_add_tcase(suite, hgv);
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
