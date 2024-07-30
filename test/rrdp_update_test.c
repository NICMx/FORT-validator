#include <check.h>

#include "alloc.c"
#include "base64.c"
#include "cachent.c"
#include "common.c"
#include "json_util.c"
#include "mock.c"
#include "rrdp.c"
#include "types/path.c"
#include "types/url.c"

/* Mocks */

MOCK_VOID(fnstack_push, char const *file)
MOCK_VOID(fnstack_pop, void)
MOCK_UINT(config_get_rrdp_delta_threshold, 5, void)
MOCK_VOID(__delete_node_cb, struct cache_node const *node)
MOCK(hash_get_sha256, struct hash_algorithm const *, NULL, void)
MOCK_INT(hash_validate_file, 0, struct hash_algorithm const *algorithm,
    char const *path, unsigned char const *expected, size_t expected_len)
MOCK_INT(file_write_full, 0, char const *path, unsigned char *content,
    size_t content_len)

int
cache_tmpfile(char **filename)
{
	*filename = pstrdup("tmp/a");
	return 0;
}

int
http_download(char const *url, char const *path, curl_off_t ims, bool *changed)
{
	printf("http_download(): %s -> %s\n", url, path);
	if (changed)
		*changed = true;
	return 0;
}

static char const *dls[8];
static unsigned int d;

int
relax_ng_parse(const char *path, xml_read_cb cb, void *arg)
{
	xmlTextReaderPtr reader;
	int read;

	/* TODO (warning) "XML_CHAR_ENCODING_NONE" */
	reader = xmlReaderForMemory(dls[d], strlen(dls[d]), path, "UTF-8", 0);
	if (reader == NULL)
		return pr_val_err("Unable to open %s (Cause unavailable).", path);
	d++;

	while ((read = xmlTextReaderRead(reader)) == 1) {
//		ck_assert_int_eq(1, xmlTextReaderIsValid(reader));
		ck_assert_int_eq(0, cb(reader, arg));
	}

	ck_assert_int_eq(read, 0);
//	ck_assert_int_eq(1, xmlTextReaderIsValid(reader));

	xmlFreeTextReader(reader);
	return 0;
}

/* Tests */

#define NHDR(serial) "<notification "					\
		"xmlns=\"http://www.ripe.net/rpki/rrdp\" "		\
		"version=\"1\" "					\
		"session_id=\"9df4b597-af9e-4dca-bdda-719cce2c4e28\" "	\
		"serial=\"" serial "\">\n"
#define NSS(u, h) "\t<snapshot uri=\"" u "\" hash=\"" h "\"/>\n"
#define NTAIL "</notification>"

#define SHDR(serial) "<snapshot "					\
		"xmlns=\"http://www.ripe.net/rpki/rrdp\" "		\
		"version=\"1\" "					\
		"session_id=\"9df4b597-af9e-4dca-bdda-719cce2c4e28\" "	\
		"serial=\"" serial "\">\n"
#define STAIL "</snapshot>"

#define PBLSH(u, c) "<publish uri=\"" u "\">" c "</publish>"

START_TEST(startup)
{
	struct cache_node notif;

	memset(&notif, 0, sizeof(notif));
	notif.url = "https://host/notification.xml";
	notif.path = "tmp/https/host/notification.xml";
	notif.name = "notification.xml";

	dls[0] = NHDR("3")
		NSS("https://host/9d-8/3/snapshot.xml", "0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD")
		NTAIL;
	dls[1] = SHDR("3") PBLSH("rsync://a/b/c.cer", "Rm9ydA==") STAIL;
	dls[2] = NULL;
	d = 0;

	ck_assert_int_eq(0, rrdp_update(&notif));
}
END_TEST

static Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *update;

	update = tcase_create("update");
	tcase_add_test(update, startup);

	suite = suite_create("RRDP Update");
	suite_add_tcase(suite, update);

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
