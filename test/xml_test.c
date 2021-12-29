#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include <libxml/xmlreader.h>
#include "impersonator.c"
#include "log.c"
#include "str_token.c"
#include "xml/relax_ng.c"

struct reader_ctx {
	unsigned int delta_count;
	unsigned int snapshot_count;
	char *serial;
};

static int
reader_cb(xmlTextReaderPtr reader, void *arg)
{
	struct reader_ctx *ctx = arg;
	xmlChar const *name;
	xmlChar *serial;
	int error;

	name = xmlTextReaderConstLocalName(reader);
	switch (xmlTextReaderNodeType(reader)) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST "delta")) {
			ctx->delta_count++;
		} else if (xmlStrEqual(name, BAD_CAST "snapshot")) {
			ctx->snapshot_count++;
		} else if (xmlStrEqual(name, BAD_CAST "notification")) {
			serial = xmlTextReaderGetAttribute(reader,
			    BAD_CAST "serial");
			if (serial == NULL)
				return -EINVAL;
			error = string_clone(serial, xmlStrlen(serial),
			    &ctx->serial);
			xmlFree(serial);
			if (error)
				return error;
		} else {
			return -EINVAL;
		}
		break;
	default:
		return 0;
	}

	return 0;
}

START_TEST(relax_ng_valid)
{
	struct reader_ctx ctx;
	char const *url = "xml/notification.xml";

	ctx.delta_count = 0;
	ctx.snapshot_count = 0;
	ctx.serial = NULL;
	relax_ng_init();
	ck_assert_int_eq(relax_ng_parse(url, reader_cb, &ctx), 0);
	ck_assert_int_eq(ctx.snapshot_count, 1);
	ck_assert_int_eq(ctx.delta_count, 5);
	ck_assert_str_eq(ctx.serial, "1510");
	free(ctx.serial);
	relax_ng_cleanup();
}
END_TEST

Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *validate;

	validate = tcase_create("Validate");
	tcase_add_test(validate, relax_ng_valid);

	suite = suite_create("xml_test()");
	suite_add_tcase(suite, validate);

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
