/* This will create some test files in "tmp/". Needs permissions. */

#include <check.h>
#include <sys/queue.h>

#include "alloc.c"
#include "base64.c"
#include "common.c"
#include "cache.c"
#include "cachetmp.c"
#include "file.c"
#include "hash.c"
#include "json_util.c"
#include "mock.c"
#include "mock_https.c"
#include "rrdp_util.h"
#include "relax_ng.c"
#include "rrdp.c"
#include "types/map.c"
#include "types/path.c"
#include "types/str.c"
#include "types/url.c"

/* Mocks */

static unsigned int rsync_counter; /* Times the rsync function was called */

static void
touch_file(char const *dir)
{
	char cmd[64];
	ck_assert(snprintf(cmd, sizeof(cmd), "touch %s/file", dir) < sizeof(cmd));
	ck_assert_int_eq(0, system(cmd));
}

int
rsync_download(char const *url, char const *path)
{
	rsync_counter++;

	if (dl_error)
		return dl_error;

	ck_assert_int_eq(0, mkdir_p(path, true));
	touch_file(path);

	return 0;
}

MOCK_VOID(__delete_node_cb, struct cache_node const *node)

/* Helpers */

static void
setup_test(void)
{
	dl_error = 0;
	ck_assert_int_eq(0, system("rm -rf tmp"));
	init_tables();
	ck_assert_int_eq(0, system("mkdir -p tmp/rsync tmp/https tmp/rrdp tmp/fallback"));
}

static struct cache_cage *
run_dl_rsync(char *caRepository, unsigned int expected_calls)
{
	struct sia_uris sias = { .caRepository = caRepository };
	struct cache_cage *cage;

	rsync_counter = 0;
	https_counter = 0;
	printf("---- Downloading... ----\n");
	cage = cache_refresh_sias(&sias);
	printf("---- Downloaded. ----\n");
	ck_assert_uint_eq(expected_calls, rsync_counter);
	ck_assert_uint_eq(0, https_counter);

	return cage;
}

static void
run_dl_https(char const *url, unsigned int expected_calls,
    char const *expected_result)
{
	char const *result;

	rsync_counter = 0;
	https_counter = 0;
	printf("---- Downloading... ----\n");
	result = cache_refresh_url(url);
	printf("---- Downloaded. ----\n");
	ck_assert_uint_eq(0, rsync_counter);
	ck_assert_uint_eq(expected_calls, https_counter);

	ck_assert_str(expected_result, result);
	ck_assert_str(NULL, cache_fallback_url(url));
}


static void
ck_cage(struct cache_cage *cage, char const *url,
    char const *refresh, char const *fallback)
{
	struct cache_node *bkp;

	ck_assert_str(refresh, cage_map_file(cage, url));

	bkp = cage->refresh;
	cage_disable_refresh(cage);

	ck_assert_str(fallback, cage_map_file(cage, url));

	cage->refresh = bkp;
}

static int
print_file(const char *fpath, const struct stat *sb, int typeflag,
    struct FTW *ftwbuf)
{
	printf("- %s\n", fpath);
	return 0;
}

static void
print_tree(void)
{
	printf("Tree nodes:\n");
	cache_print();
	printf("\n");

	printf("Files in cache:\n");
	ck_assert_int_eq(0, nftw("tmp/", print_file, 32, FTW_PHYS));
	printf("\n");
}

static void
queue_commit(char const *caRepository, char const *path1, char const *path2)
{
	struct rpp rpp = { 0 };

	rpp.nfiles = 2;
	rpp.files = pzalloc(rpp.nfiles * sizeof(struct cache_mapping));
	rpp.files[0].url = path_join(caRepository, "manifest.mft");
	rpp.files[0].path = pstrdup(path1);
	rpp.files[1].url = path_join(caRepository, "cert.cer");
	rpp.files[1].path = pstrdup(path2);

	cache_commit_rpp(caRepository, &rpp);
}

/* Only validates the first character of the file. */
static void
ck_file(char const *path, char const *expected)
{
	FILE *file;
	char actual[2];

	file = fopen(path, "rb");
	if (!file)
		ck_abort_msg("fopen(%s): %s", path, strerror(errno));
	ck_assert_int_eq(1, fread(actual, 1, 1, file));
	fclose(file);
	actual[1] = 0;

	ck_assert_str_eq(expected, actual);
}

static va_list fs_valist;

static int
ck_filesystem_file(const char *fpath, const struct stat *sb, int typeflag,
    struct FTW *ftwbuf)
{
	static va_list args;
	char const *path;
	bool found = false;

	if ((sb->st_mode & S_IFMT) != S_IFREG)
		return 0;

	va_copy(args, fs_valist);
	while ((path = va_arg(args, char const *)) != NULL)
		if (strcmp(fpath, path) == 0) {
			found = true;
			break;
		}
	va_end(args);

	if (!found)
		ck_abort_msg("Unexpected file: %s", fpath);
	return 0;
}

static void
ck_filesystem(char const *root, ...)
{
	char const *path;
	int error;

	va_start(fs_valist, root);
	while ((path = va_arg(fs_valist, char const *)) != NULL)
		ck_file(path, va_arg(fs_valist, char const *));
	va_end(fs_valist);

	va_start(fs_valist, root);
	errno = 0;
	error = nftw(root, ck_filesystem_file, 32, FTW_PHYS);
	if (error)
		ck_abort_msg("nftw: %d %d", error, errno);
	va_end(fs_valist);
}

static void
init_node_rsync(struct cache_node *node, char *url, char *path,
    int fresh, int dlerr)
{
	node->map.url = url;
	node->map.path = path;
	node->fresh = fresh;
	node->dlerr = dlerr;
	node->rrdp = NULL;
}

static void
init_node_https(struct cache_node *node, char *url, char *path,
    int fresh, int dlerr)
{
	node->map.url = url;
	node->map.path = path;
	node->fresh = fresh;
	node->dlerr = dlerr;
	node->rrdp = NULL;
}

static void
ck_cache_node_eq(struct cache_node *expected, struct cache_node *actual)
{
	ck_assert_str_eq(expected->map.url, actual->map.url);
	ck_assert_str_eq(expected->map.path, actual->map.path);
	ck_assert_int_eq(expected->fresh, actual->fresh);
	ck_assert_int_eq(expected->dlerr, actual->dlerr);
	if (expected->rrdp == NULL)
		ck_assert_ptr_eq(expected->rrdp, actual->rrdp);
	// XXX else
}

static void
ck_cache(struct cache_node *expecteds, struct cache_table *tbl)
{
	struct cache_node *actual, *tmp;
	unsigned int n;

	for (n = 0; expecteds[n].map.url != NULL; n++)
		;
	ck_assert_uint_eq(n, HASH_COUNT(tbl->nodes));

	n = 0;
	HASH_ITER(hh, tbl->nodes, actual, tmp) {
		ck_cache_node_eq(&expecteds[n], actual);
		n++;
	}
}

static void
ck_cache_rsync(struct cache_node *expected)
{
	ck_cache(expected, &cache.rsync);
}

static void
ck_cache_https(struct cache_node *expected)
{
	ck_cache(expected, &cache.https);
}

static time_t
get_days_ago(int days)
{
	time_t tt_now, last_week;
	struct tm tm;
	int error;

	tt_now = time_fatal();
	if (localtime_r(&tt_now, &tm) == NULL) {
		error = errno;
		pr_crit("localtime_r(tt, &tm) returned error: %s",
		    strerror(error));
	}
	tm.tm_mday -= days;
	last_week = mktime(&tm);
	if (last_week == (time_t) -1)
		pr_crit("mktime(tm) returned (time_t) -1.");

	return last_week;
}

static time_t epoch;

static void
unfreshen(struct cache_table *tbl, struct cache_node *node)
{
	node->fresh = 0;
}

static int
nftw_unfreshen(const char *fpath, const struct stat *sb, int typeflag,
    struct FTW *ftwbuf)
{
	struct timespec times[2];

	times[0].tv_sec = epoch;
	times[0].tv_nsec = 0;
	times[1].tv_sec = epoch;
	times[1].tv_nsec = 0;

	ck_assert_int_eq(0, utimensat(AT_FDCWD, fpath, times, AT_SYMLINK_NOFOLLOW));

	return 0;
}

static void
new_iteration(bool outdate)
{
	epoch = outdate ? get_days_ago(30) : get_days_ago(1);

	pr_op_debug("--- Unfreshening... ---");
	cache_foreach(unfreshen);
	ck_assert_int_eq(0, nftw("tmp/rsync", nftw_unfreshen, 32, FTW_PHYS));

	pr_op_debug("---- Tree now stale. ----");
	cache_print();
}

static void
cleanup_test(void)
{
	dl_error = 0;
	cache_commit();
}

/* Tests */

START_TEST(test_cache_download_rsync)
{
	struct cache_node nodes[4] = { 0 };
	struct cache_cage *cage;

	setup_test();

	printf("==== Startup ====\n");
	cage = run_dl_rsync("rsync://a.b.c/d", 1);
	ck_assert_ptr_ne(NULL, cage);
	ck_cage(cage, "rsync://a.b.c/d", "tmp/rsync/0", NULL);
	ck_cage(cage, "rsync://a.b.c/d/e/f.cer", "tmp/rsync/0/e/f.cer", NULL);
	init_node_rsync(&nodes[0], "rsync://a.b.c/d", "tmp/rsync/0", 1, 0);
	ck_cache_rsync(nodes);
	free(cage);

	printf("==== Redownload same file, nothing should happen ====\n");
	cage = run_dl_rsync("rsync://a.b.c/d", 0);
	ck_assert_ptr_ne(NULL, cage);
	ck_cage(cage, "rsync://a.b.c/d", "tmp/rsync/0", NULL);
	ck_cage(cage, "rsync://a.b.c/d/e/f.cer", "tmp/rsync/0/e/f.cer", NULL);
	ck_cache_rsync(nodes);
	free(cage);

	/*
	 * rsyncs are recursive, which means if we've been recently asked to
	 * download d, we needn't bother redownloading d/e.
	 */
	printf("==== Don't redownload child ====\n");
	cage = run_dl_rsync("rsync://a.b.c/d/e", 0);
	ck_assert_ptr_ne(NULL, cage);
	ck_cage(cage, "rsync://a.b.c/d", "tmp/rsync/0", NULL);
	ck_cage(cage, "rsync://a.b.c/d/e/f.cer", "tmp/rsync/0/e/f.cer", NULL);
	ck_cache_rsync(nodes);
	free(cage);

	/*
	 * rsyncs get truncated, because it results in much faster
	 * synchronization in practice.
	 * This is not defined in any RFCs; it's an effective standard,
	 * and there would be consequences for violating it.
	 */
	printf("==== rsync truncated ====\n");
	cage = run_dl_rsync("rsync://x.y.z/m/n/o", 1);
	ck_assert_ptr_ne(NULL, cage);
	ck_cage(cage, "rsync://x.y.z/m", "tmp/rsync/1", NULL);
	ck_cage(cage, "rsync://x.y.z/m/n/o", "tmp/rsync/1/n/o", NULL);
	init_node_rsync(&nodes[1], "rsync://x.y.z/m", "tmp/rsync/1", 1, 0);
	ck_cache_rsync(nodes);
	free(cage);

	printf("==== Sibling ====\n");
	cage = run_dl_rsync("rsync://a.b.c/e/f", 1);
	ck_assert_ptr_ne(NULL, cage);
	ck_cage(cage, "rsync://a.b.c/e", "tmp/rsync/2", NULL);
	ck_cage(cage, "rsync://a.b.c/e/f/x/y/z", "tmp/rsync/2/f/x/y/z", NULL);
	init_node_rsync(&nodes[2], "rsync://a.b.c/e", "tmp/rsync/2", 1, 0);
	ck_cache_rsync(nodes);
	free(cage);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_download_rsync_error)
{
	struct cache_node nodes[3] = { 0 };

	setup_test();

	init_node_rsync(&nodes[0], "rsync://a.b.c/d", "tmp/rsync/0", 1, 0);
	init_node_rsync(&nodes[1], "rsync://a.b.c/e", "tmp/rsync/1", 1, EINVAL);

	printf("==== Startup ====\n");
	dl_error = 0;
	free(run_dl_rsync("rsync://a.b.c/d", 1));
	dl_error = EINVAL;
	ck_assert_ptr_eq(NULL, run_dl_rsync("rsync://a.b.c/e", 1));
	ck_cache_rsync(nodes);

	printf("==== Regardless of error, not reattempted because same iteration ====\n");
	dl_error = EINVAL;
	ck_assert_ptr_eq(NULL, run_dl_rsync("rsync://a.b.c/e", 0));
	ck_cache_rsync(nodes);
	dl_error = 0;
	ck_assert_ptr_eq(NULL, run_dl_rsync("rsync://a.b.c/e", 0));
	ck_cache_rsync(nodes);

	cleanup_test();
}
END_TEST

START_TEST(test_rsync_commit)
{
	unsigned int i;

	setup_test();

	ck_assert_int_eq(0, system("mkdir -p tmp/rsync/0 tmp/rsync/1 tmp/rsync/2 tmp/rsync/3"));

	/* RPP0: Will remain constant */
	ck_assert_int_eq(0, write_simple_file("tmp/rsync/0/0", "A"));
	ck_assert_int_eq(0, write_simple_file("tmp/rsync/0/1", "B"));
	/* RPP1: Will be added in its second cycle */
	ck_assert_int_eq(0, write_simple_file("tmp/rsync/1/0", "C"));
	ck_assert_int_eq(0, write_simple_file("tmp/rsync/1/1", "D"));
	/* RPP2: Will be removed in its second cycle */
	ck_assert_int_eq(0, write_simple_file("tmp/rsync/2/0", "E"));
	ck_assert_int_eq(0, write_simple_file("tmp/rsync/2/1", "F"));
	/* RPP3: Will be updated in its second cycle */
	ck_assert_int_eq(0, write_simple_file("tmp/rsync/3/0", "G")); /* Keeper */
	ck_assert_int_eq(0, write_simple_file("tmp/rsync/3/1", "H")); /* Added */
	ck_assert_int_eq(0, write_simple_file("tmp/rsync/3/2", "I")); /* Removed */

	/* Commit 1: Empty -> Empty */
	/* Commit 2: Empty -> Empty (just free noise) */
	for (i = 0; i < 2; i++) {
		commit_fallbacks();
		ck_filesystem("tmp/fallback", NULL);

		new_iteration(false);
	}

	/* Commit 3: Empty -> Populated */
	queue_commit("rsync://domain/mod/rpp0", "tmp/rsync/0/0", "tmp/rsync/0/1");
	queue_commit("rsync://domain/mod/rpp2", "tmp/rsync/2/0", "tmp/rsync/2/1");
	queue_commit("rsync://domain/mod/rpp3", "tmp/rsync/3/0", "tmp/rsync/3/2");
	commit_fallbacks();
	ck_filesystem("tmp/fallback",
	    /* RPP0 */ "tmp/fallback/0/0", "A", "tmp/fallback/0/1", "B",
	    /* RPP2 */ "tmp/fallback/1/0", "E", "tmp/fallback/1/1", "F",
	    /* RPP3 */ "tmp/fallback/2/0", "G", "tmp/fallback/2/1", "I",
	    NULL);

	new_iteration(false);

	/* Commit 4: Populated -> Populated */
	/* XXX check the refresh does, in fact, only return fallbacks when the RPP doesn't change */
	queue_commit("rsync://domain/mod/rpp0", "tmp/fallback/0/0", "tmp/fallback/0/1");
	queue_commit("rsync://domain/mod/rpp1", "tmp/rsync/1/0", "tmp/rsync/1/1");
	queue_commit("rsync://domain/mod/rpp3", "tmp/fallback/2/0", "tmp/rsync/3/1");
	commit_fallbacks();
	ck_filesystem("tmp/fallback",
	    /* RPP0 */ "tmp/fallback/0/0", "A", "tmp/fallback/0/1", "B",
	    /* RPP3 */ "tmp/fallback/2/0", "G", "tmp/fallback/2/2", "H",
	    /* RPP1 */ "tmp/fallback/3/0", "C", "tmp/fallback/3/1", "D",
	    NULL);

	new_iteration(false);

	/* Commit 5: Populated -> Empty */
	commit_fallbacks();
	ck_filesystem("tmp/fallback", NULL);

	cache_foreach(delete_node);
}
END_TEST

START_TEST(test_cache_download_https)
{
	struct cache_node nodes[4] = { 0 };

	setup_test();

	printf("==== Download file ====\n");
	run_dl_https("https://a.b.c/d/e", 1, "tmp/https/0");
	init_node_https(&nodes[0], "https://a.b.c/d/e", "tmp/https/0", 1, 0);
	ck_cache_https(nodes);

	printf("==== Download same file ====\n");
	run_dl_https("https://a.b.c/d/e", 0, "tmp/https/0");
	ck_cache_https(nodes);

	printf("==== Download something else 1 ====\n");
	run_dl_https("https://a.b.c/e", 1, "tmp/https/1");
	init_node_https(&nodes[1], "https://a.b.c/e", "tmp/https/1", 1, 0);
	ck_cache_https(nodes);

	printf("==== Download something else 2 ====\n");
	run_dl_https("https://x.y.z/e", 1, "tmp/https/2");
	init_node_https(&nodes[2], "https://x.y.z/e", "tmp/https/2", 1, 0);
	ck_cache_https(nodes);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_download_https_error)
{
	struct cache_node nodes[3] = { 0 };

	setup_test();

	init_node_https(&nodes[0], "https://a.b.c/d", "tmp/https/0", 1, 0);
	init_node_https(&nodes[1], "https://a.b.c/e", "tmp/https/1", 1, EINVAL);

	printf("==== Startup ====\n");
	dl_error = 0;
	run_dl_https("https://a.b.c/d", 1, "tmp/https/0");
	dl_error = EINVAL;
	run_dl_https("https://a.b.c/e", 1, NULL);
	ck_cache_https(nodes);

	printf("==== Regardless of error, not reattempted because same iteration ====\n");
	dl_error = -EINVAL;
	run_dl_https("https://a.b.c/d", 0, "tmp/https/0");
	run_dl_https("https://a.b.c/e", 0, NULL);
	dl_error = 0;
	run_dl_https("https://a.b.c/d", 0, "tmp/https/0");
	run_dl_https("https://a.b.c/e", 0, NULL);
	ck_cache_https(nodes);

	cleanup_test();
}
END_TEST

/* See comments at test_rsync_commit(). */
START_TEST(test_https_commit)
{
	struct cache_mapping map;
	unsigned int i;

	setup_test();

	ck_assert_int_eq(0, write_simple_file("tmp/https/50", "A")); /* Keeper */
	ck_assert_int_eq(0, write_simple_file("tmp/https/51", "B")); /* Added */
	ck_assert_int_eq(0, write_simple_file("tmp/https/52", "C")); /* Removed */

	/* 1, 2 */
	for (i = 0; i < 2; i++) {
		commit_fallbacks();
		ck_filesystem("tmp/fallback", NULL);

		new_iteration(false);
	}

	/* 3 */
	map.url = "https://domain/rpki/ta50.cer";
	map.path = "tmp/https/50";
	cache_commit_file(&map);
	map.url = "https://domain/rpki/ta52.cer";
	map.path = "tmp/https/52";
	cache_commit_file(&map);
	commit_fallbacks();
	ck_filesystem("tmp/fallback",
	    "tmp/fallback/0", "A",
	    "tmp/fallback/1", "C",
	    NULL);

	new_iteration(false);

	/* 4 */
	map.url = "https://domain/rpki/ta50.cer";
	map.path = "tmp/fallback/0";
	cache_commit_file(&map);
	map.url = "https://domain/rpki/ta51.cer";
	map.path = "tmp/https/51";
	cache_commit_file(&map);
	commit_fallbacks();
	ck_filesystem("tmp/fallback",
	    "tmp/fallback/0", "A",
	    "tmp/fallback/2", "B",
	    NULL);

	new_iteration(false);

	/* 5 */
	commit_fallbacks();
	ck_filesystem("tmp/fallback", NULL);

	cache_foreach(delete_node);
}
END_TEST

/* See comments at test_rsync_commit(). */
START_TEST(test_rrdp_commit)
{
	unsigned int i;

	setup_test();

	ck_assert_int_eq(0, system("mkdir -p tmp/rrdp/0 tmp/rrdp/1 tmp/rrdp/2 tmp/rrdp/3"));

	ck_assert_int_eq(0, write_simple_file("tmp/rrdp/0/0", "A"));
	ck_assert_int_eq(0, write_simple_file("tmp/rrdp/0/1", "B"));
	ck_assert_int_eq(0, write_simple_file("tmp/rrdp/1/0", "C"));
	ck_assert_int_eq(0, write_simple_file("tmp/rrdp/1/1", "D"));
	ck_assert_int_eq(0, write_simple_file("tmp/rrdp/2/0", "E"));
	ck_assert_int_eq(0, write_simple_file("tmp/rrdp/2/1", "F"));
	ck_assert_int_eq(0, write_simple_file("tmp/rrdp/3/0", "G"));
	ck_assert_int_eq(0, write_simple_file("tmp/rrdp/3/1", "H"));
	ck_assert_int_eq(0, write_simple_file("tmp/rrdp/3/2", "I"));

	/* 1, 2 */
	for (i = 0; i < 2; i++) {
		commit_fallbacks();
		ck_filesystem("tmp/fallback", NULL);

		new_iteration(false);
	}

	/* 3 */
	queue_commit("rsync://domain/mod/rpp0", "tmp/rrdp/0/0", "tmp/rrdp/0/1");
	queue_commit("rsync://domain/mod/rpp2", "tmp/rrdp/2/0", "tmp/rrdp/2/1");
	queue_commit("rsync://domain/mod/rpp3", "tmp/rrdp/3/0", "tmp/rrdp/3/2");
	commit_fallbacks();
	ck_filesystem("tmp/fallback",
	    "tmp/fallback/0/0", "A", "tmp/fallback/0/1", "B",
	    "tmp/fallback/1/0", "E", "tmp/fallback/1/1", "F",
	    "tmp/fallback/2/0", "G", "tmp/fallback/2/1", "I",
	    NULL);

	new_iteration(false);

	/* 4 */
	queue_commit("rsync://domain/mod/rpp0", "tmp/fallback/0/0", "tmp/fallback/0/1");
	queue_commit("rsync://domain/mod/rpp1", "tmp/rrdp/1/0", "tmp/rrdp/1/1");
	queue_commit("rsync://domain/mod/rpp3", "tmp/fallback/2/0", "tmp/rrdp/3/1");
	commit_fallbacks();
	ck_filesystem("tmp/fallback",
	    "tmp/fallback/0/0", "A", "tmp/fallback/0/1", "B",
	    "tmp/fallback/2/0", "G", "tmp/fallback/2/2", "H",
	    "tmp/fallback/3/0", "C", "tmp/fallback/3/1", "D",
	    NULL);

	new_iteration(false);

	/* 5 */
	commit_fallbacks();
	ck_filesystem("tmp/fallback", NULL);

	cache_foreach(delete_node);
}
END_TEST

START_TEST(test_collisions)
{
	/*
	 * Request
	 *
	 * 1. rsync://a.b.c/d/e/f/
	 * 2. https://x.y.z/m/n/o.notification -> rsync://a.b.c/d/e/f/
	 *
	 * - None validates
	 * - rsync validates
	 * - https validates
	 * - Both validate
	 */

	struct sia_uris sias;

	ck_assert_int_eq(0, hash_setup());
	ck_assert_int_eq(0, relax_ng_init());

	setup_test();

	printf("==== 1 ====\n");

	/* Context: rsync */
	sias.caRepository = "rsync://a.b.c/mod/rpp1";
	sias.rpkiManifest = "rsync://a.b.c/mod/rpp1/m.mft";
	sias.rpkiNotify = NULL;

	rsync_counter = https_counter = 0;
	ck_assert_int_eq(0, cache_download_alt(&sias, okay, NULL));
	ck_assert_uint_eq(1, rsync_counter);
	ck_assert_uint_eq(0, https_counter);

	cache_print();

	/*
	 * Context: notification "https://a.b.c/d/notification.xml".
	 * Both point to the same caRepository (RPP).
	 *
	 * This is either two benign RPPs coexisting (likely because of key
	 * rollover), or one malicious RPP is trying to overwrite the other.
	 *
	 * So they need to be cached separately. We cannot reuse the RPP simply
	 * because the caRepositories are identical.
	 */
	sias.rpkiNotify = "https://a.b.c/d/notification.xml";

	dls[0] = NHDR("12") NSS("https://a.b.c/d/snapshot.xml",
	    "d880c0e3136695636f73f8fb6340245182f4b19bd4b092679b9002ad427dc380")
	    NTAIL;
	dls[1] = SHDR("12") PBLSH("rsync://a.b.c/mod/rpp1/m.mft",
	    "ZXhhbXBsZTE=") STAIL;
	dls[2] = NULL;

	rsync_counter = https_counter = 0;
	ck_assert_int_eq(0, cache_download_alt(&sias, okay, NULL));
	ck_assert_uint_eq(0, rsync_counter);
	ck_assert_uint_eq(2, https_counter);

	cache_print();

	// XXX
}

START_TEST(test_dots)
{
	setup_test();

	run_dl_https("https://a.b.c/d", 0, 1);
	ck_cache_https(
		hnode(HE2UP,
			hnode(HO2UP("a.b.c"),
				hftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL), NULL), NULL));

	run_dl_https("https://a.b.c/d/.", 0, 0);
	ck_cache_https(
		hnode(HE2UP,
			hnode(HO2UP("a.b.c"),
				hftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL), NULL), NULL));

	run_dl_https("https://a.b.c/d/e/..", 0, 0);
	ck_cache_https(
		hnode(HE2UP,
			hnode(HO2UP("a.b.c"),
				hftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL), NULL), NULL));

	run_dl_https("https://a.b.c/./d/../e", 0, 1);
	ck_cache_https(
		hnode(HE2UP,
			hnode(HO2UP("a.b.c"),
				hftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL),
				hftnode(HO2UP("a.b.c/e"), HFULL, "tmp/tmp/1", NULL), NULL), NULL));

	cleanup_test();
}
END_TEST

START_TEST(test_tal_json)
{
	json_t *json;
	char *str;

	setup_test();

	ck_assert_int_eq(0, system("rm -rf tmp/"));
	ck_assert_int_eq(0, system("mkdir -p tmp"));

	add_node(cache, NODE("rsync://a.b.c/d", 0, 1, 0));
	add_node(cache, NODE("rsync://a.b.c/e", 1, 0, 0));
	add_node(cache, NODE("rsync://x.y.z/e", 0, 1, 0));
	add_node(cache, NODE("https://a/b", 1, 1, 0));
	add_node(cache, node("https://a/c", 0, 0, 1, 0, 1));

	json = build_tal_json(cache);
	ck_assert_int_eq(0, json_dump_file(json, "tmp/" TAL_METAFILE, JSON_COMPACT));

	str = json_dumps(json, /* JSON_INDENT(4) */ JSON_COMPACT);
	json_decref(json);

	ck_assert_str_eq(
	    "[{\"type\":\"RPP\",\"url\":\"rsync://a.b.c/d\",\"attempt-timestamp\":\"1970-01-01T00:00:00Z\",\"attempt-result\":0,\"success-timestamp\":\"1970-01-01T00:00:00Z\"},"
	    "{\"type\":\"RPP\",\"url\":\"rsync://a.b.c/e\",\"attempt-timestamp\":\"1970-01-01T00:00:00Z\",\"attempt-result\":1},"
	    "{\"type\":\"RPP\",\"url\":\"rsync://x.y.z/e\",\"attempt-timestamp\":\"1970-01-01T00:00:00Z\",\"attempt-result\":0,\"success-timestamp\":\"1970-01-01T00:00:00Z\"},"
	    "{\"type\":\"TA (HTTP)\",\"url\":\"https://a/b\",\"attempt-timestamp\":\"1970-01-01T00:00:00Z\",\"attempt-result\":1,\"success-timestamp\":\"1970-01-01T00:00:00Z\"},"
	    "{\"type\":\"RRDP Notification\",\"url\":\"https://a/c\",\"attempt-timestamp\":\"1970-01-01T00:00:00Z\",\"attempt-result\":0,\"success-timestamp\":\"1970-01-01T00:00:00Z\"}]",
	    str);
	free(str);

	cache_reset(cache);

	load_tal_json(cache);
	ck_assert_ptr_ne(NULL, cache->ht);

	ck_cache(
	    NODE("rsync://a.b.c/d", 0, 1, 0),
	    NODE("rsync://a.b.c/e", 1, 0, 0),
	    NODE("rsync://x.y.z/e", 0, 1, 0),
	    NODE("https://a/b", 1, 1, 0),
	    NODE("https://a/c", 0, 1, 0),
	    NULL);

	cleanup_test();
}
END_TEST

static void
prepare_map_list(struct map_list *maps, ...)
{
	char const *str;
	enum map_type type;
	struct cache_mapping *map;
	va_list args;

	maps_init(maps);

	va_start(args, maps);
	while ((str = va_arg(args, char const *)) != NULL) {
		if (url_is_https(str))
			type = MAP_HTTP;
		else if (url_is_rsync(str))
			type = MAP_RSYNC;
		else
			ck_abort_msg("Bad protocol: %s", str);
		ck_assert_int_eq(0, map_create(&map, type, str));
		maps_add(maps, map);
	}
	va_end(args);
}

#define PREPARE_MAP_LIST(maps, ...) prepare_map_list(maps, ##__VA_ARGS__, NULL)

START_TEST(test_recover)
{
	struct map_list maps;

	setup_test();

	/* Query on empty database */
	PREPARE_MAP_LIST(&maps, "rsync://a.b.c/d", "https://a.b.c/d");
	ck_assert_ptr_eq(NULL, cache_recover(cache, &maps));
	maps_cleanup(&maps);

	/* Only first URI is cached */
	cache_reset(cache);
	run_cache_download("rsync://a/b/c", 0, 1, 0);

	PREPARE_MAP_LIST(&maps, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(maps.array[0], cache_recover(cache, &maps));
	maps_cleanup(&maps);

	/* Only second URI is cached */
	cache_reset(cache);
	run_cache_download("https://d/e", 0, 0, 1);

	PREPARE_MAP_LIST(&maps, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(maps.array[1], cache_recover(cache, &maps));
	maps_cleanup(&maps);

	/* Only third URI is cached */
	cache_reset(cache);
	run_cache_download("https://f", 0, 0, 1);

	PREPARE_MAP_LIST(&maps, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(maps.array[2], cache_recover(cache, &maps));
	maps_cleanup(&maps);

	/* None was cached */
	cache_reset(cache);
	run_cache_download("rsync://d/e", 0, 1, 0);

	PREPARE_MAP_LIST(&maps, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(NULL, cache_recover(cache, &maps));
	maps_cleanup(&maps);

	/*
	 * At present, cache_recover() can only be called after all of a
	 * download's URLs yielded failure.
	 * However, node.error can still be zero. This happens when the download
	 * was successful, but the RRDP code wasn't able to expand the snapshot
	 * or deltas.
	 */
	cache_reset(cache);

	add_node(cache, node("rsync/a/1", 100, 0, 1, 100, 0));
	add_node(cache, node("rsync/a/2", 100, 1, 1, 100, 0));
	add_node(cache, node("rsync/a/3", 200, 0, 1, 100, 0));
	add_node(cache, node("rsync/a/4", 200, 1, 1, 100, 0));
	add_node(cache, node("rsync/a/5", 100, 0, 1, 200, 0));
	add_node(cache, node("rsync/a/6", 100, 1, 1, 200, 0));
	add_node(cache, node("rsync/b/1", 100, 0, 0, 100, 0));
	add_node(cache, node("rsync/b/2", 100, 1, 0, 100, 0));
	add_node(cache, node("rsync/b/3", 200, 0, 0, 100, 0));
	add_node(cache, node("rsync/b/4", 200, 1, 0, 100, 0));
	add_node(cache, node("rsync/b/5", 100, 0, 0, 200, 0));
	add_node(cache, node("rsync/b/6", 100, 1, 0, 200, 0));

	/* Multiple successful caches: Prioritize the most recent one */
	PREPARE_MAP_LIST(&maps, "rsync://a/1", "rsync://a/3", "rsync://a/5");
	ck_assert_ptr_eq(maps.array[2], cache_recover(cache, &maps));
	maps_cleanup(&maps);

	PREPARE_MAP_LIST(&maps, "rsync://a/5", "rsync://a/1", "rsync://a/3");
	ck_assert_ptr_eq(maps.array[0], cache_recover(cache, &maps));
	maps_cleanup(&maps);

	/* No successful caches: No viable candidates */
	PREPARE_MAP_LIST(&maps, "rsync://b/2", "rsync://b/4", "rsync://b/6");
	ck_assert_ptr_eq(NULL, cache_recover(cache, &maps));
	maps_cleanup(&maps);

	/* Status: CNF_SUCCESS is better than 0. */
	PREPARE_MAP_LIST(&maps, "rsync://b/1", "rsync://a/1");
	ck_assert_ptr_eq(maps.array[1], cache_recover(cache, &maps));
	maps_cleanup(&maps);

	/*
	 * If CNF_SUCCESS && error, Fort will probably run into a problem
	 * reading the cached directory, because it's either outdated or
	 * recently corrupted.
	 * But it should still TRY to read it, as there's a chance the
	 * outdatedness is not that severe.
	 */
	PREPARE_MAP_LIST(&maps, "rsync://a/2", "rsync://b/2");
	ck_assert_ptr_eq(maps.array[0], cache_recover(cache, &maps));
	maps_cleanup(&maps);

	/* Parents of downloaded nodes */
	PREPARE_MAP_LIST(&maps, "rsync://a", "rsync://b");
	ck_assert_ptr_eq(NULL, cache_recover(cache, &maps));
	maps_cleanup(&maps);

	/* Try them all at the same time */
	PREPARE_MAP_LIST(&maps,
	    "rsync://a", "rsync://a/1", "rsync://a/2", "rsync://a/3",
	    "rsync://a/4", "rsync://a/5", "rsync://a/6",
	    "rsync://b", "rsync://b/1", "rsync://b/2", "rsync://b/3",
	    "rsync://b/4", "rsync://b/5", "rsync://b/6",
	    "rsync://e/1");
	ck_assert_ptr_eq(maps.array[5], cache_recover(cache, &maps));
	maps_cleanup(&maps);

	cleanup_test();
}
END_TEST

/* Boilerplate */

static Suite *thread_pool_suite(void)
{
	Suite *suite;
	TCase *rsync, *https, *rrdp, *mix, *dot, *meta, *recover;

	rsync = tcase_create("rsync");
	tcase_add_test(rsync, test_cache_download_rsync);
	tcase_add_test(rsync, test_cache_download_rsync_error);
	tcase_add_test(rsync, test_rsync_commit);

	https = tcase_create("https");
	tcase_add_test(https, test_cache_download_https);
	tcase_add_test(https, test_cache_download_https_error);
	tcase_add_test(https, test_https_commit);

	rrdp = tcase_create("rrdp");
	tcase_add_test(rrdp, test_rrdp_commit);

	mix = tcase_create("mix");
	tcase_add_test(https, test_collisions);

	dot = tcase_create("dot");
	tcase_add_test(dot, test_dots);

	meta = tcase_create(TAL_METAFILE);
	tcase_add_test(meta, test_tal_json);

	recover = tcase_create("recover");
	tcase_add_test(recover, test_recover);

	suite = suite_create("local-cache");
	suite_add_tcase(suite, rsync);
	suite_add_tcase(suite, https);
	suite_add_tcase(suite, rrdp);
	suite_add_tcase(suite, mix);
	suite_add_tcase(suite, dot);
	suite_add_tcase(suite, meta);
	suite_add_tcase(suite, recover);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = thread_pool_suite();
	dls[0] = "Fort\n";

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
