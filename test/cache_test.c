/* This will create some test files in "tmp/". Needs permissions. */

#include <check.h>
#include <sys/queue.h>

#include "alloc.c"
#include "common.c"
#include "cache.c"
#include "cachent.c"
#include "cachetmp.c"
#include "cache_util.c"
#include "file.c"
#include "mock.c"
#include "mock_https.c"
#include "types/path.c"
#include "types/str.c"
#include "types/url.c"

/* Mocks */

static unsigned int rsync_counter; /* Times the rsync function was called */

int
rsync_download(char const *src, char const *dst, char const *cmpdir)
{
	char cmd[64];

	rsync_counter++;

	if (dl_error)
		return dl_error;

	ck_assert_int_eq(0, mkdir_p(dst, true, 0777));

	ck_assert(snprintf(cmd, sizeof(cmd), "touch %s/file", dst) < sizeof(cmd));
	ck_assert_int_eq(0, system(cmd));

	return 0;
}

MOCK_ABORT_INT(rrdp_update, struct cache_node *notif)
__MOCK_ABORT(rrdp_notif2json, json_t *, NULL, struct cachefile_notification *notif)
MOCK_VOID(rrdp_notif_free, struct cachefile_notification *notif)
MOCK_ABORT_INT(rrdp_json2notif, json_t *json, struct cachefile_notification **result)
MOCK_VOID(__delete_node_cb, struct cache_node const *node)

/* Helpers */

static void
setup_test(void)
{
	dl_error = 0;
	ck_assert_int_eq(0, system("rm -rf tmp/"));
	cache_prepare();
	ck_assert_int_eq(0, system("mkdir -p tmp/rsync tmp/https tmp/tmp"));
}

static int
okay(struct cache_node *node, void *arg)
{
	// XXX ensure the rsync and RRDP codes do this
	node->flags |= CNF_VALID;
	return 0;
}

static void
run_dl_rsync(char const *caRepository, int expected_error,
    unsigned int expected_calls)
{
	struct sia_uris sias;

	sias.caRepository = pstrdup(caRepository);
	sias.rpkiNotify = NULL;
	sias.rpkiManifest = NULL;

	rsync_counter = 0;
	https_counter = 0;
	printf("---- Downloading... ----\n");
	ck_assert_int_eq(expected_error, cache_download_alt(&sias, okay, NULL));
	printf("---- Downloaded. ----\n");
	ck_assert_uint_eq(expected_calls, rsync_counter);
	ck_assert_uint_eq(0, https_counter);

	sias_cleanup(&sias);
}

static void
run_dl_https(char const *url, int expected_error, unsigned int expected_calls)
{
	struct strlist uris;

	strlist_init(&uris);
	strlist_add(&uris, pstrdup(url));

	rsync_counter = 0;
	https_counter = 0;
	printf("---- Downloading... ----\n");
	ck_assert_int_eq(expected_error, cache_download_uri(&uris, okay, NULL));
	printf("---- Downloaded. ----\n");
	ck_assert_uint_eq(0, rsync_counter);
	ck_assert_uint_eq(expected_calls, https_counter);

	strlist_cleanup(&uris);
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
run_cleanup(void)
{
	print_tree();

	pr_op_debug("---- Cleaning up... ----");
	cleanup_cache();
	pr_op_debug("---- Cleant. ----");
}

static bool
ck_path(struct cache_node *node)
{
	int error;

	if (!node->tmppath)
		return true;

	error = file_exists(node->tmppath);
	if (error)
		ck_abort_msg("Missing file in cache: %s (%s)", node->tmppath,
		    strerror(error));

	return true;
}

static void
ck_cache(struct cache_node *rsync, struct cache_node *https)
{
	printf("---- Validating tree... ----\n");

	printf("Expected nodes:\n");
	cachent_print(rsync);
	cachent_print(https);
	printf("\n");

	print_tree();

	/* Compare expected and cache */
	// XXX fix
	PR_DEBUG_MSG("%s", ">> Comparing expected and cache...");
	cachent_traverse(rsync, ck_path);
	cachent_traverse(https, ck_path);

	/* Compare expected and actual */
	PR_DEBUG_MSG("%s", ">> Comparing expected and actual...");
	ck_assert_cachent_eq(rsync, cache.rsync);
	ck_assert_cachent_eq(https, cache.https);

	cachent_delete(rsync);
	cachent_delete(https);

	printf("---- Validated. ----\n");
}

static void
ck_cache_rsync(struct cache_node *rsync)
{
	ck_cache(rsync, hunode(HE2UP, NULL));
}

static void
ck_cache_https(struct cache_node *https)
{
	ck_cache(runode(RE2UP, NULL), https);
}

static time_t
get_days_ago(int days)
{
	time_t tt_now, last_week;
	struct tm tm;
	int error;

	tt_now = time(NULL);
	if (tt_now == (time_t) -1)
		pr_crit("time(NULL) returned (time_t) -1.");
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

static bool
unfreshen(struct cache_node *node)
{
	PR_DEBUG_MSG("Unfreshening %s.", node->url);
	node->flags &= ~(CNF_FRESH | CNF_VALID);
	node->mtim = epoch;
	return true;
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
	PR_DEBUG_MSG("changing times of %s", fpath);

	ck_assert_int_eq(0, utimensat(AT_FDCWD, fpath, times, AT_SYMLINK_NOFOLLOW));

	return 0;
}

static void
new_iteration(bool outdate)
{
	pr_op_debug("--- Unfreshening... ---");
	epoch = outdate ? get_days_ago(30) : get_days_ago(1);
	cachent_traverse(cache.rsync, unfreshen);
	cachent_traverse(cache.https, unfreshen);
	ck_assert_int_eq(0, nftw("tmp/rsync", nftw_unfreshen, 32, FTW_PHYS));
	ck_assert_int_eq(0, nftw("tmp/https", nftw_unfreshen, 32, FTW_PHYS));

	pr_op_debug("---- Tree now stale. ----");
	cache_print();
}

static void
cleanup_test(void)
{
	dl_error = 0;
	cache_commit();
//	ck_assert_int_eq(0, system("rm -rf tmp/"));
}

/* Tests */

static const int DOWNLOADED = CNF_RSYNC | CNF_CACHED | CNF_FRESH;
static const int VALIDATED = RSYNC_INHERIT | CNF_VALID;
static const int FULL = DOWNLOADED | VALIDATED;
static const int STALE = CNF_RSYNC | CNF_CACHED;
/* Intermediary between a downloaded and a validated node */
static const int BRANCH = RSYNC_INHERIT;
static const int FAILED = CNF_FRESH;

START_TEST(test_cache_download_rsync)
{
	setup_test();

	printf("==== Startup ====\n");
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				ruftnode(RO2UP("a.b.c/d"), FULL, "tmp/tmp/0", NULL), NULL), NULL));

	printf("==== Redownload same file, nothing should happen ====\n");
	run_dl_rsync("rsync://a.b.c/d", 0, 0);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				ruftnode(RO2UP("a.b.c/d"), FULL, "tmp/tmp/0", NULL), NULL), NULL));

	/*
	 * rsyncs are recursive, which means if we've been recently asked to
	 * download d, we needn't bother redownloading d/e.
	 */
	printf("==== Don't redownload child ====\n");
	run_dl_rsync("rsync://a.b.c/d/e", 0, 0);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				ruftnode(RO2UP("a.b.c/d"), FULL, "tmp/tmp/0",
					rufnode(RO2UP("a.b.c/d/e"), VALIDATED, NULL), NULL), NULL), NULL));

	/*
	 * rsyncs get truncated, because it results in much faster
	 * synchronization in practice.
	 * This is not defined in any RFCs; it's an effective standard,
	 * and there would be consequences for violating it.
	 */
	printf("==== rsync truncated ====\n");
	run_dl_rsync("rsync://x.y.z/m/n/o", 0, 1);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				ruftnode(RO2UP("a.b.c/d"), FULL, "tmp/tmp/0",
					rufnode(RO2UP("a.b.c/d/e"), VALIDATED, NULL), NULL), NULL),
			runode(RO2UP("x.y.z"),
				ruftnode(RO2UP("x.y.z/m"), DOWNLOADED, "tmp/tmp/1",
					rufnode(RO2UP("x.y.z/m/n"), BRANCH,
						rufnode(RO2UP("x.y.z/m/n/o"), VALIDATED, NULL), NULL), NULL), NULL), NULL));

	printf("==== Sibling ====\n");
	run_dl_rsync("rsync://a.b.c/e/f", 0, 1);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				ruftnode(RO2UP("a.b.c/d"), FULL, "tmp/tmp/0",
					rufnode(RO2UP("a.b.c/d/e"), VALIDATED, NULL), NULL),
				ruftnode(RO2UP("a.b.c/e"), DOWNLOADED, "tmp/tmp/2",
					rufnode(RO2UP("a.b.c/e/f"), VALIDATED, NULL), NULL), NULL),
			runode(RO2UP("x.y.z"),
				ruftnode(RO2UP("x.y.z/m"), DOWNLOADED, "tmp/tmp/1",
					rufnode(RO2UP("x.y.z/m/n"), BRANCH,
						rufnode(RO2UP("x.y.z/m/n/o"), VALIDATED, NULL), NULL), NULL), NULL), NULL));

	cleanup_test();
}
END_TEST

START_TEST(test_cache_download_rsync_error)
{
	setup_test();

	printf("==== Startup ====\n");
	dl_error = 0;
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	dl_error = -EINVAL;
	run_dl_rsync("rsync://a.b.c/e", -EINVAL, 1);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				ruftnode(RO2UP("a.b.c/d"), FULL, "tmp/tmp/0", NULL),
				rufnode(RO2UP("a.b.c/e"), FAILED, NULL), NULL), NULL));

	printf("==== Regardless of error, not reattempted because same iteration ====\n");
	dl_error = EINVAL;
	run_dl_rsync("rsync://a.b.c/e", -EINVAL, 0);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				ruftnode(RO2UP("a.b.c/d"), FULL, "tmp/tmp/0", NULL),
				rufnode(RO2UP("a.b.c/e"), FAILED, NULL), NULL), NULL));

	dl_error = 0;
	run_dl_rsync("rsync://a.b.c/e", -EINVAL, 0);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				ruftnode(RO2UP("a.b.c/d"), FULL, "tmp/tmp/0", NULL),
				rufnode(RO2UP("a.b.c/e"), FAILED, NULL), NULL), NULL));

	cleanup_test();
}
END_TEST

START_TEST(test_cache_cleanup_rsync)
{
	setup_test();

	printf("==== First iteration: Tree is created. No prunes, because nothing's outdated ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/d"), FULL, NULL),
				rufnode(RO2UP("a.b.c/e"), FULL, NULL), NULL), NULL));

	printf("==== One iteration with no changes, for paranoia ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/d"), FULL, NULL),
				rufnode(RO2UP("a.b.c/e"), FULL, NULL), NULL), NULL));

	printf("==== Add one sibling ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_dl_rsync("rsync://a.b.c/f", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/d"), FULL, NULL),
				rufnode(RO2UP("a.b.c/e"), FULL, NULL),
				rufnode(RO2UP("a.b.c/f"), FULL, NULL), NULL), NULL));

	printf("==== Nodes don't get updated, but they're still too young ====\n");
	new_iteration(false);
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/d"), STALE, NULL),
				rufnode(RO2UP("a.b.c/e"), STALE, NULL),
				rufnode(RO2UP("a.b.c/f"), STALE, NULL), NULL), NULL));

	printf("==== Remove some branches ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/d"), FULL, NULL), NULL), NULL));

	printf("==== Remove old branch and add sibling at the same time ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/e"), FULL, NULL), NULL), NULL));

	printf("==== Try child ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/e/f/g", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/e"), FULL, NULL), NULL), NULL));

	printf("==== Parent again ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/e"), FULL, NULL), NULL), NULL));

	printf("==== Empty the tree ====\n");
	new_iteration(true);
	run_cleanup();
	ck_cache_rsync(runode(RE2UP, NULL));


	printf("==== Node exists, but file doesn't ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_dl_rsync("rsync://a.b.c/f", 0, 1);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				ruftnode(RO2UP("a.b.c/e"), FULL, "tmp/tmp/B", NULL),
				ruftnode(RO2UP("a.b.c/f"), FULL, "tmp/tmp/C", NULL), NULL), NULL));
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/e"), FULL, NULL),
				rufnode(RO2UP("a.b.c/f"), FULL, NULL), NULL), NULL));
	ck_assert_int_eq(0, file_rm_rf("tmp/rsync/a.b.c/f"));
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/e"), FULL, NULL), NULL), NULL));

	cleanup_test();
}
END_TEST

START_TEST(test_cache_cleanup_rsync_error)
{
	setup_test();

	printf("==== Set up ====\n");
	dl_error = 0;
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	dl_error = -EINVAL;
	run_dl_rsync("rsync://a.b.c/e", -EINVAL, 1);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				ruftnode(RO2UP("a.b.c/d"), FULL, "tmp/tmp/0", NULL),
				rufnode(RO2UP("a.b.c/e"), FAILED, NULL), NULL), NULL));

	printf("==== Node deleted because file doesn't exist ====\n");
	run_cleanup();
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/d"), FULL, NULL), NULL), NULL));

	printf("==== Node and file preserved because young ====\n");
	/* (Deletion does not depend on success or failure.) */
	new_iteration(false);
	dl_error = -EINVAL;
	run_dl_rsync("rsync://a.b.c/d", -EINVAL, 1);
	ck_cache_rsync(
		runode(RE2UP,
			runode(RO2UP("a.b.c"),
				rufnode(RO2UP("a.b.c/d"), DOWNLOADED, NULL), NULL), NULL));

	printf("==== Error node deleted because old ====\n");
	new_iteration(true);
	run_cleanup();
	ck_cache_rsync(runode(RE2UP, NULL));

	cleanup_test();
}
END_TEST

/* XXX ================================================================ */

static const int HDOWNLOADED = CNF_CACHED | CNF_FRESH;
static const int HVALIDATED = CNF_CACHED | CNF_VALID;
static const int HFULL = HDOWNLOADED | HVALIDATED;
static const int HFAILED = CNF_FRESH;

START_TEST(test_cache_download_https)
{
	setup_test();

	printf("==== Download *file* e ====\n");
	run_dl_https("https://a.b.c/d/e", 0, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hunode(HO2UP("a.b.c/d"),
					huftnode(HO2UP("a.b.c/d/e"), HFULL, "tmp/tmp/0", NULL), NULL), NULL), NULL));

	printf("==== Download something else 1 ====\n");
	run_dl_https("https://a.b.c/e", 0, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hunode(HO2UP("a.b.c/d"),
					huftnode(HO2UP("a.b.c/d/e"), HFULL, "tmp/tmp/0", NULL), NULL),
				huftnode(HO2UP("a.b.c/e"), HFULL, "tmp/tmp/1", NULL), NULL), NULL));

	printf("==== Download something else 2 ====\n");
	run_dl_https("https://x.y.z/e", 0, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hunode(HO2UP("a.b.c/d"),
					huftnode(HO2UP("a.b.c/d/e"), HFULL, "tmp/tmp/0", NULL), NULL),
				huftnode(HO2UP("a.b.c/e"), HFULL, "tmp/tmp/1", NULL), NULL),
			hunode(HO2UP("x.y.z"),
				huftnode(HO2UP("x.y.z/e"), HFULL, "tmp/tmp/2", NULL), NULL), NULL));

	cleanup_test();
}
END_TEST

START_TEST(test_cache_download_https_error)
{
	setup_test();

	printf("==== Startup ====\n");
	dl_error = 0;
	run_dl_https("https://a.b.c/d", 0, 1);
	dl_error = -EINVAL;
	run_dl_https("https://a.b.c/e", -EINVAL, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL),
				huftnode(HO2UP("a.b.c/e"), HFAILED, NULL, NULL), NULL), NULL));

	printf("==== Regardless of error, not reattempted because same iteration ====\n");
	dl_error = -EINVAL;
	run_dl_https("https://a.b.c/d", 0, 0);
	dl_error = 0;
	run_dl_https("https://a.b.c/e", -EINVAL, 0);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL),
				huftnode(HO2UP("a.b.c/e"), HFAILED, NULL, NULL), NULL), NULL));

	cleanup_test();
}
END_TEST

// XXX not testing alts so far

START_TEST(test_cache_cleanup_https)
{
	setup_test();

	printf("==== First iteration; make a tree and clean it ====\n");
	new_iteration(true);
	run_dl_https("https://a.b.c/d", 0, 1);
	run_dl_https("https://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/d"), HFULL, NULL),
				hufnode(HO2UP("a.b.c/e"), HFULL, NULL), NULL), NULL));

	printf("==== Remove one branch ====\n");
	new_iteration(true);
	run_dl_https("https://a.b.c/d", 0, 1);
	run_cleanup();
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/d"), HFULL, NULL), NULL), NULL));

	printf("==== Change the one branch ====\n");
	new_iteration(true);
	run_dl_https("https://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/e"), HFULL, NULL), NULL), NULL));

	printf("==== Add a child to the same branch, do not update the old one ====\n");
	new_iteration(true);
	run_dl_https("https://a.b.c/e/f/g", 0, 1);
	run_cleanup();
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hunode(HO2UP("a.b.c/e"),
					hunode(HO2UP("a.b.c/e/f"),
						hufnode(HO2UP("a.b.c/e/f/g"), HFULL, NULL), NULL), NULL), NULL), NULL));

	printf("====  Download parent, do not update child ====\n");
	/* (Children need to die, because parent is now a file) */
	new_iteration(true);
	run_dl_https("https://a.b.c/e/f", 0, 1);
	run_cleanup();
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hunode(HO2UP("a.b.c/e"),
					hufnode(HO2UP("a.b.c/e/f"), HFULL, NULL), NULL), NULL), NULL));

	printf("==== Do it again ====\n");
	new_iteration(true);
	run_dl_https("https://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/e"), HFULL, NULL), NULL), NULL));


	printf("==== Empty the tree ====\n");
	new_iteration(true);
	run_cleanup();
	ck_cache_https(hunode(HE2UP, NULL));

	printf("==== Node exists, but file doesn't ====\n");
	new_iteration(true);
	run_dl_https("https://a.b.c/e", 0, 1);
	run_dl_https("https://a.b.c/f/g/h", 0, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/e"), HFULL, "tmp/tmp/7", NULL),
				hunode(HO2UP("a.b.c/f"),
					hunode(HO2UP("a.b.c/f/g"),
						huftnode(HO2UP("a.b.c/f/g/h"), HFULL, "tmp/tmp/8", NULL), NULL), NULL), NULL), NULL));
	run_cleanup(); /* Move from tmp/tmp to tmp/https */
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/e"), HFULL, NULL),
				hunode(HO2UP("a.b.c/f"),
					hunode(HO2UP("a.b.c/f/g"),
						hufnode(HO2UP("a.b.c/f/g/h"), HFULL, NULL), NULL), NULL), NULL), NULL));
	ck_assert_int_eq(0, file_rm_rf("tmp/https/a.b.c/f/g/h"));
	run_cleanup(); /* Actual test */
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/e"), HFULL, NULL), NULL), NULL));

	printf("==== Temporal version disappears before we get a commit ====\n");
	new_iteration(true);
	run_dl_https("https://a.b.c/e", 0, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/e"), HFULL, "tmp/tmp/9", NULL), NULL), NULL));
	ck_assert_int_eq(0, file_rm_rf("tmp/tmp/9"));
	run_cleanup();
	ck_cache_https(hunode(HE2UP, NULL));

	printf("==== Temporal version disappears after we get a commit ====\n");
	new_iteration(true);
	run_dl_https("https://a.b.c/e", 0, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/e"), HFULL, "tmp/tmp/A", NULL), NULL), NULL));
	run_cleanup(); /* Commit */
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/e"), HFULL, NULL, NULL), NULL), NULL));
	new_iteration(false);
	run_dl_https("https://a.b.c/e", 0, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/e"), HFULL, "tmp/tmp/B", NULL), NULL), NULL));
	ck_assert_int_eq(0, file_rm_rf("tmp/tmp/B"));
	run_cleanup();
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/e"), HFULL, NULL), NULL), NULL));

	cleanup_test();
}
END_TEST

START_TEST(test_cache_cleanup_https_error)
{
	setup_test();

	printf("==== Set up ====\n");
	dl_error = 0;
	run_dl_https("https://a.b.c/d", 0, 1);
	dl_error = -EINVAL;
	run_dl_https("https://a.b.c/e", -EINVAL, 1);
	PR_DEBUG;
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL),
				hufnode(HO2UP("a.b.c/e"), HFAILED, NULL), NULL), NULL));

	printf("==== Deleted because file ENOENT ====\n");
	run_cleanup();
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/d"), HFULL, NULL), NULL), NULL));

	printf("==== Fail d ====\n");
	new_iteration(false);
	dl_error = -EINVAL;
	run_dl_https("https://a.b.c/d", -EINVAL, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/d"), CNF_CACHED | CNF_FRESH, NULL), NULL), NULL));

	printf("==== Not deleted, because not old ====\n");
	new_iteration(false);
	run_cleanup();
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				hufnode(HO2UP("a.b.c/d"), CNF_CACHED, NULL), NULL), NULL));

	printf("==== Become old ====\n");
	new_iteration(true);
	run_cleanup();
	ck_cache_https(hunode(HE2UP, NULL));

	cleanup_test();
}
END_TEST

START_TEST(test_dots)
{
	setup_test();

	run_dl_https("https://a.b.c/d", 0, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL), NULL), NULL));

	run_dl_https("https://a.b.c/d/.", 0, 0);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL), NULL), NULL));

	run_dl_https("https://a.b.c/d/e/..", 0, 0);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL), NULL), NULL));

	run_dl_https("https://a.b.c/./d/../e", 0, 1);
	ck_cache_https(
		hunode(HE2UP,
			hunode(HO2UP("a.b.c"),
				huftnode(HO2UP("a.b.c/d"), HFULL, "tmp/tmp/0", NULL),
				huftnode(HO2UP("a.b.c/e"), HFULL, "tmp/tmp/1", NULL), NULL), NULL));

	cleanup_test();
}
END_TEST
//
//START_TEST(test_tal_json)
//{
//	json_t *json;
//	char *str;
//
//	setup_test();
//
//	ck_assert_int_eq(0, system("rm -rf tmp/"));
//	ck_assert_int_eq(0, system("mkdir -p tmp"));
//
//	add_node(cache, NODE("rsync://a.b.c/d", 0, 1, 0));
//	add_node(cache, NODE("rsync://a.b.c/e", 1, 0, 0));
//	add_node(cache, NODE("rsync://x.y.z/e", 0, 1, 0));
//	add_node(cache, NODE("https://a/b", 1, 1, 0));
//	add_node(cache, node("https://a/c", 0, 0, 1, 0, 1));
//
//	json = build_tal_json(cache);
//	ck_assert_int_eq(0, json_dump_file(json, "tmp/" TAL_METAFILE, JSON_COMPACT));
//
//	str = json_dumps(json, /* JSON_INDENT(4) */ JSON_COMPACT);
//	json_decref(json);
//
//	ck_assert_str_eq(
//	    "[{\"type\":\"RPP\",\"url\":\"rsync://a.b.c/d\",\"attempt-timestamp\":\"1970-01-01T00:00:00Z\",\"attempt-result\":0,\"success-timestamp\":\"1970-01-01T00:00:00Z\"},"
//	    "{\"type\":\"RPP\",\"url\":\"rsync://a.b.c/e\",\"attempt-timestamp\":\"1970-01-01T00:00:00Z\",\"attempt-result\":1},"
//	    "{\"type\":\"RPP\",\"url\":\"rsync://x.y.z/e\",\"attempt-timestamp\":\"1970-01-01T00:00:00Z\",\"attempt-result\":0,\"success-timestamp\":\"1970-01-01T00:00:00Z\"},"
//	    "{\"type\":\"TA (HTTP)\",\"url\":\"https://a/b\",\"attempt-timestamp\":\"1970-01-01T00:00:00Z\",\"attempt-result\":1,\"success-timestamp\":\"1970-01-01T00:00:00Z\"},"
//	    "{\"type\":\"RRDP Notification\",\"url\":\"https://a/c\",\"attempt-timestamp\":\"1970-01-01T00:00:00Z\",\"attempt-result\":0,\"success-timestamp\":\"1970-01-01T00:00:00Z\"}]",
//	    str);
//	free(str);
//
//	cache_reset(cache);
//
//	load_tal_json(cache);
//	ck_assert_ptr_ne(NULL, cache->ht);
//
//	ck_cache(
//	    NODE("rsync://a.b.c/d", 0, 1, 0),
//	    NODE("rsync://a.b.c/e", 1, 0, 0),
//	    NODE("rsync://x.y.z/e", 0, 1, 0),
//	    NODE("https://a/b", 1, 1, 0),
//	    NODE("https://a/c", 0, 1, 0),
//	    NULL);
//
//	cleanup_test();
//}
//END_TEST
//
//static void
//prepare_map_list(struct map_list *maps, ...)
//{
//	char const *str;
//	enum map_type type;
//	struct cache_mapping *map;
//	va_list args;
//
//	maps_init(maps);
//
//	va_start(args, maps);
//	while ((str = va_arg(args, char const *)) != NULL) {
//		if (str_starts_with(str, "https://"))
//			type = MAP_HTTP;
//		else if (str_starts_with(str, "rsync://"))
//			type = MAP_RSYNC;
//		else
//			ck_abort_msg("Bad protocol: %s", str);
//		ck_assert_int_eq(0, map_create(&map, type, str));
//		maps_add(maps, map);
//	}
//	va_end(args);
//}

//#define PREPARE_MAP_LIST(maps, ...) prepare_map_list(maps, ##__VA_ARGS__, NULL)
//
//START_TEST(test_recover)
//{
//	struct map_list maps;
//
//	setup_test();
//
//	/* Query on empty database */
//	PREPARE_MAP_LIST(&maps, "rsync://a.b.c/d", "https://a.b.c/d");
//	ck_assert_ptr_eq(NULL, cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	/* Only first URI is cached */
//	cache_reset(cache);
//	run_cache_download("rsync://a/b/c", 0, 1, 0);
//
//	PREPARE_MAP_LIST(&maps, "rsync://a/b/c", "https://d/e", "https://f");
//	ck_assert_ptr_eq(maps.array[0], cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	/* Only second URI is cached */
//	cache_reset(cache);
//	run_cache_download("https://d/e", 0, 0, 1);
//
//	PREPARE_MAP_LIST(&maps, "rsync://a/b/c", "https://d/e", "https://f");
//	ck_assert_ptr_eq(maps.array[1], cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	/* Only third URI is cached */
//	cache_reset(cache);
//	run_cache_download("https://f", 0, 0, 1);
//
//	PREPARE_MAP_LIST(&maps, "rsync://a/b/c", "https://d/e", "https://f");
//	ck_assert_ptr_eq(maps.array[2], cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	/* None was cached */
//	cache_reset(cache);
//	run_cache_download("rsync://d/e", 0, 1, 0);
//
//	PREPARE_MAP_LIST(&maps, "rsync://a/b/c", "https://d/e", "https://f");
//	ck_assert_ptr_eq(NULL, cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	/*
//	 * At present, cache_recover() can only be called after all of a
//	 * download's URLs yielded failure.
//	 * However, node.error can still be zero. This happens when the download
//	 * was successful, but the RRDP code wasn't able to expand the snapshot
//	 * or deltas.
//	 */
//	cache_reset(cache);
//
//	add_node(cache, node("rsync/a/1", 100, 0, 1, 100, 0));
//	add_node(cache, node("rsync/a/2", 100, 1, 1, 100, 0));
//	add_node(cache, node("rsync/a/3", 200, 0, 1, 100, 0));
//	add_node(cache, node("rsync/a/4", 200, 1, 1, 100, 0));
//	add_node(cache, node("rsync/a/5", 100, 0, 1, 200, 0));
//	add_node(cache, node("rsync/a/6", 100, 1, 1, 200, 0));
//	add_node(cache, node("rsync/b/1", 100, 0, 0, 100, 0));
//	add_node(cache, node("rsync/b/2", 100, 1, 0, 100, 0));
//	add_node(cache, node("rsync/b/3", 200, 0, 0, 100, 0));
//	add_node(cache, node("rsync/b/4", 200, 1, 0, 100, 0));
//	add_node(cache, node("rsync/b/5", 100, 0, 0, 200, 0));
//	add_node(cache, node("rsync/b/6", 100, 1, 0, 200, 0));
//
//	/* Multiple successful caches: Prioritize the most recent one */
//	PREPARE_MAP_LIST(&maps, "rsync://a/1", "rsync://a/3", "rsync://a/5");
//	ck_assert_ptr_eq(maps.array[2], cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	PREPARE_MAP_LIST(&maps, "rsync://a/5", "rsync://a/1", "rsync://a/3");
//	ck_assert_ptr_eq(maps.array[0], cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	/* No successful caches: No viable candidates */
//	PREPARE_MAP_LIST(&maps, "rsync://b/2", "rsync://b/4", "rsync://b/6");
//	ck_assert_ptr_eq(NULL, cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	/* Status: CNF_SUCCESS is better than 0. */
//	PREPARE_MAP_LIST(&maps, "rsync://b/1", "rsync://a/1");
//	ck_assert_ptr_eq(maps.array[1], cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	/*
//	 * If CNF_SUCCESS && error, Fort will probably run into a problem
//	 * reading the cached directory, because it's either outdated or
//	 * recently corrupted.
//	 * But it should still TRY to read it, as there's a chance the
//	 * outdatedness is not that severe.
//	 */
//	PREPARE_MAP_LIST(&maps, "rsync://a/2", "rsync://b/2");
//	ck_assert_ptr_eq(maps.array[0], cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	/* Parents of downloaded nodes */
//	PREPARE_MAP_LIST(&maps, "rsync://a", "rsync://b");
//	ck_assert_ptr_eq(NULL, cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	/* Try them all at the same time */
//	PREPARE_MAP_LIST(&maps,
//	    "rsync://a", "rsync://a/1", "rsync://a/2", "rsync://a/3",
//	    "rsync://a/4", "rsync://a/5", "rsync://a/6",
//	    "rsync://b", "rsync://b/1", "rsync://b/2", "rsync://b/3",
//	    "rsync://b/4", "rsync://b/5", "rsync://b/6",
//	    "rsync://e/1");
//	ck_assert_ptr_eq(maps.array[5], cache_recover(cache, &maps));
//	maps_cleanup(&maps);
//
//	cleanup_test();
//}
//END_TEST

/* Boilerplate */

static Suite *thread_pool_suite(void)
{
	Suite *suite;
	TCase *rsync, *https, *dot, *meta, *recover;

	rsync = tcase_create("rsync");
	tcase_add_test(rsync, test_cache_download_rsync);
	tcase_add_test(rsync, test_cache_download_rsync_error);
	tcase_add_test(rsync, test_cache_cleanup_rsync);
	tcase_add_test(rsync, test_cache_cleanup_rsync_error);

	https = tcase_create("https");
	tcase_add_test(https, test_cache_download_https);
	tcase_add_test(https, test_cache_download_https_error);
	tcase_add_test(https, test_cache_cleanup_https);
	tcase_add_test(https, test_cache_cleanup_https_error);

	dot = tcase_create("dot");
	tcase_add_test(dot, test_dots);

	meta = tcase_create(TAL_METAFILE);
//	tcase_add_test(meta, test_tal_json);

	recover = tcase_create("recover");
//	tcase_add_test(recover, test_recover);

	suite = suite_create("local-cache");
	suite_add_tcase(suite, rsync);
	suite_add_tcase(suite, https);
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
