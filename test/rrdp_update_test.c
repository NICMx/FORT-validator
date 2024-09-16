#include <check.h>

#include "alloc.c"
#include "base64.c"
#include "cachent.c"
#include "cachetmp.c"
#include "cache_util.c"
#include "common.c"
#include "file.c"
#include "hash.c"
#include "json_util.c"
#include "mock.c"
#include "mock_https.c"
#include "relax_ng.c"
#include "rrdp.c"
#include "rrdp_util.h"
#include "types/path.c"
#include "types/url.c"

/* Mocks */

MOCK_VOID(__delete_node_cb, struct cache_node const *node)

/* Utils */

static void
setup_test(void)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));
	ck_assert_int_eq(0, system("mkdir -p tmp/rsync tmp/https tmp/tmp"));
	ck_assert_int_eq(0, hash_setup());
	ck_assert_int_eq(0, relax_ng_init());
}

static void
cleanup_test(void)
{
//	ck_assert_int_eq(0, system("rm -rf tmp/"));
	hash_teardown();
	relax_ng_cleanup();
}

static void
ck_file(char const *path)
{
	FILE *file;
	char buffer[8] = { 0 };

	file = fopen(path, "rb");
	ck_assert_ptr_ne(NULL, file);
	ck_assert_int_eq(5, fread(buffer, 1, 8, file));
	ck_assert_int_ne(0, feof(file));
	ck_assert_int_eq(0, fclose(file));
	ck_assert_str_eq("Fort\n", buffer);
}

/* Tests */

START_TEST(startup)
{
#define NOTIF_PATH "tmp/https/host/notification.xml"
	struct cache_node notif;

	setup_test();

	memset(&notif, 0, sizeof(notif));
	notif.url = "https://host/notification.xml";
	notif.path = NOTIF_PATH;
	notif.name = "notification.xml";

	dls[0] = NHDR("3")
		NSS("https://host/9d-8/3/snapshot.xml", "0c84fb949e7b5379ae091b86c41bb1a33cb91636b154b86ad1b1dedd44651a25")
		NTAIL;
	dls[1] = SHDR("3") PBLSH("rsync://a/b/c.cer", "Rm9ydAo=") STAIL;
	dls[2] = NULL;
	https_counter = 0;

	ck_assert_int_eq(0, rrdp_update(&notif));
	ck_assert_uint_eq(2, https_counter);
	ck_file("tmp/tmp/0/a/b/c.cer");
	ck_assert_cachent_eq(
		rftnode("rsync://", NOTIF_PATH, 0, "tmp/tmp/0",
			rftnode("rsync://a", NOTIF_PATH "/a", 0, "tmp/tmp/0/a",
				rftnode("rsync://a/b", NOTIF_PATH "/a/b", 0, "tmp/tmp/0/a/b",
					rftnode("rsync://a/b/c.cer", NOTIF_PATH "/a/b/c.cer", 0, "tmp/tmp/0/a/b/c.cer", NULL),
					NULL),
				NULL),
			NULL),
		notif.rrdp.subtree
	);

	dls[1] = NULL;
	https_counter = 0;
	ck_assert_int_eq(0, rrdp_update(&notif));
	ck_assert_uint_eq(1, https_counter);
	ck_file("tmp/tmp/0/a/b/c.cer");
	ck_assert_cachent_eq(
		rftnode("rsync://", NOTIF_PATH, 0, "tmp/tmp/0",
			rftnode("rsync://a", NOTIF_PATH "/a", 0, "tmp/tmp/0/a",
				rftnode("rsync://a/b", NOTIF_PATH "/a/b", 0, "tmp/tmp/0/a/b",
					rftnode("rsync://a/b/c.cer", NOTIF_PATH "/a/b/c.cer", 0, "tmp/tmp/0/a/b/c.cer", NULL),
					NULL),
				NULL),
			NULL),
		notif.rrdp.subtree
	);

	cleanup_test();
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
