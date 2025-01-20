#include <check.h>

#include "alloc.c"
#include "base64.c"
#include "cachetmp.c"
#include "common.c"
#include "file.c"
#include "hash.c"
#include "json_util.c"
#include "mock.c"
#include "mock_https.c"
#include "relax_ng.c"
#include "rrdp.c"
#include "rrdp_util.h"
#include "types/map.c"
#include "types/path.c"
#include "types/str.c"
#include "types/url.c"

/* Utils */

static void
setup_test(void)
{
	ck_assert_int_eq(0, system("rm -rf https/ rrdp/ tmp/"));
	ck_assert_int_eq(0, system("mkdir https/ rrdp/ tmp/"));
	ck_assert_int_eq(0, hash_setup());
	ck_assert_int_eq(0, relax_ng_init());
}

static void
cleanup_test(void)
{
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

/* XXX (test) Add delta hashes */
static void
ck_state(char const *session, char const *serial, unsigned long seq_id,
    struct cache_mapping *maps, struct rrdp_state *actual)
{
	unsigned int m;
	struct cache_file *node, *tmp;

	ck_assert_str_eq(session, actual->session.session_id);
	ck_assert_str_eq(serial, actual->session.serial.str);

	for (m = 0; maps[m].url != NULL; m++)
		;
	ck_assert_int_eq(m, HASH_COUNT(actual->files));

	m = 0;
	HASH_ITER(hh, actual->files, node, tmp) {
		ck_assert_str_eq(maps[m].url, node->map.url);
		ck_assert_str_eq(maps[m].path, node->map.path);
		m++;
	}
}

/* Tests */

START_TEST(startup)
{
	struct cache_mapping notif;
	struct cache_sequence seq;
	struct rrdp_state *state = NULL;
	struct cache_mapping maps[4];
	bool changed;

	setup_test();

	notif.url = "https://host/notification.xml";
	notif.path = "rrdp/0";

	seq.prefix = "rrdp";
	seq.next_id = 1;
	seq.pathlen = strlen(seq.prefix);
	seq.free_prefix = false;

	dls[0] = NHDR("3")
		NSS("https://host/9d-8/3/snapshot.xml",
		    "0c84fb949e7b5379ae091b86c41bb1a33cb91636b154b86ad1b1dedd44651a25")
		NTAIL;
	dls[1] = SHDR("3") PBLSH("rsync://a/b/c.cer", "Rm9ydAo=") STAIL;
	dls[2] = NULL;
	https_counter = 0;

	ck_assert_int_eq(0, rrdp_update(&notif, 0, &changed, &state));
	ck_assert_uint_eq(2, https_counter);
	ck_assert_uint_eq(true, changed);
	ck_file("rrdp/0/0"); /* "rrdp/<first-cage>/<c.cer>" */

	maps[0].url = "rsync://a/b/c.cer";
	maps[0].path = "rrdp/0/0";
	maps[1].url = NULL;
	ck_state(TEST_SESSION, "3", 1, maps, state);

	/* Attempt to update, server hasn't changed anything. */
	dls[1] = NULL; /* Snapshot should not redownload */
	https_counter = 0;
	ck_assert_int_eq(0, rrdp_update(&notif, 0, &changed, &state));
	ck_assert_uint_eq(1, https_counter);
	ck_assert_uint_eq(false, changed);
	ck_file("rrdp/0/0");
	ck_state(TEST_SESSION, "3", 1, maps, state);

	rrdp_state_free(state);

	// XXX Missing a looooooooooooooooooot of tests

	cleanup_test();
}
END_TEST

static Suite *create_suite(void)
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

	if (mkdir("tmp", CACHE_FILEMODE) < 0 && errno != EEXIST) {
		fprintf(stderr, "mkdir('tmp/'): %s\n", strerror(errno));
		return 1;
	}
	if (chdir("tmp") < 0) {
		fprintf(stderr, "chdir('tmp/'): %s\n", strerror(errno));
		return 1;
	}

	suite = create_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
