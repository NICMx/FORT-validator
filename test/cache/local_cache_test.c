/*
 * This test will create some temporal directories on "/tmp".
 * Needs permissions.
 */

#include <check.h>
//#include <stdarg.h>
#include <sys/queue.h>

#include "alloc.c"
#include "common.c"
#include "file.c"
//#include "json_util.c"
#include "mock.c"
#include "cache/cachent.c"
#include "cache/local_cache.c"
#include "cache/util.c"
#include "data_structure/path_builder.c"
#include "types/str.c"
#include "types/url.c"

/* Mocks */

static unsigned int rsync_counter; /* Times the rsync function was called */
static unsigned int https_counter; /* Times the https function was called */
static int dl_error;

static void
__delete_node_cb(struct cache_node const *node)
{
	/* Nothing */
}

int
rsync_download(char const *src, char const *dst, bool is_directory)
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

int
http_download(char const *url, char const *path, curl_off_t ims, bool *changed)
{
	char cmd[61];

	https_counter++;

	if (dl_error) {
		*changed = false;
		return dl_error;
	}

	ck_assert_int_eq(0, mkdir_p(path, false, 0777));

	ck_assert(snprintf(cmd, sizeof(cmd), "touch %s", path) < sizeof(cmd));
	ck_assert_int_eq(0, system(cmd));

	*changed = true;
	return 0;
}

MOCK_ABORT_INT(rrdp_update, struct cache_node *notif)
__MOCK_ABORT(rrdp_notif2json, json_t *, NULL, struct cachefile_notification *notif)
MOCK_VOID(rrdp_notif_free, struct cachefile_notification *notif)
MOCK_ABORT_INT(rrdp_json2notif, json_t *json, struct cachefile_notification **result)
MOCK(cfg_cache_threshold, time_t, 60 * 60 * 24 * 7, void)

/* Helpers */

static void
setup_test(bool dl_type)
{
	dl_error = 0;
	ck_assert_int_eq(0, system("rm -rf tmp/"));
	cache_prepare();
	ck_assert_int_eq(0, system("mkdir -p tmp/rsync"));
	ck_assert_int_eq(0, system("mkdir -p tmp/https"));
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
	static struct sia_uris sias;

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
ck_path(struct cache_node *node, char const *_)
{
	int error;

	if (!node->tmpdir)
		return true;

	error = file_exists(node->tmpdir);
	if (error)
		ck_abort_msg("Missing file in cache: %s (%s)", node->tmpdir, strerror(error));

	return true;
}

//static struct cache_node *
//cachent_find(struct cache_node *root, char const *url)
//{
//	struct cache_node *node, *child;
//	struct tokenizer tkn;
//
//	node = root;
//	token_init(&tkn, url);
//	if (!token_next(&tkn))
//		ck_abort_msg("Path too short: %s", url);
//	if (strncmp(root->name, tkn.str, tkn.len) != 0) {
//		ck_abort_msg("Root doesn't match: %s != %.*s",
//		    root->name, (int)tkn.len, tkn.str);
//	}
//
//	while (token_next(&tkn)) {
//		if (tkn.len == 1 && tkn.str[0] == '.')
//			continue;
//		if (tkn.len == 2 && tkn.str[0] == '.' && tkn.str[1] == '.')
//			node = node->parent;
//
//		HASH_FIND(hh, node->children, tkn.str, tkn.len, child);
//		if (child == NULL)
//			ck_abort_msg("Child not found: %s > %.*s",
//			    node->name, (int)tkn.len, tkn.str);
//
//		node = child;
//	}
//
//	return node;
//}

static void
ck_assert_cachent_eq(struct cache_node *expected, struct cache_node *actual)
{
	struct cache_node *echild, *achild, *tmp;

	PR_DEBUG_MSG("Comparing %s vs %s", expected->url, actual->url);

	ck_assert_str_eq(expected->url, actual->url);
	ck_assert_str_eq(expected->name, actual->name);
	ck_assert_int_eq(expected->flags, actual->flags);
	if (expected->tmpdir)
		ck_assert_str_eq(expected->tmpdir, actual->tmpdir);
	else
		ck_assert_ptr_eq(NULL, actual->tmpdir);

	HASH_ITER(hh, expected->children, echild, tmp) {
		HASH_FIND(hh, actual->children, echild->name,
		    strlen(echild->name), achild);
		if (achild == NULL)
			ck_abort_msg("Expected not found: %s", echild->url);
		ck_assert_cachent_eq(echild, achild);
	}

	HASH_ITER(hh, actual->children, achild, tmp) {
		HASH_FIND(hh, expected->children, achild->name,
		    strlen(achild->name), echild);
		if (echild == NULL)
			ck_abort_msg("Actual not found: %s", achild->url);
	}
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
	ck_cache(rsync, unode("https", NULL));
}

static time_t epoch;

static bool
unfreshen(struct cache_node *node, char const *path)
{
	PR_DEBUG_MSG("Unfreshening %s.", node->url);
	node->flags &= ~CNF_FRESH;
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
	epoch = outdate ? get_days_ago(30) : get_days_ago(1);
	cachent_traverse(cache.rsync, unfreshen);
	ck_assert_int_eq(0, nftw("tmp/rsync", nftw_unfreshen, 32, FTW_PHYS));
	ck_assert_int_eq(0, nftw("tmp/https", nftw_unfreshen, 32, FTW_PHYS));
}

//static void
//cache_reset(struct rpki_cache *cache)
//{
//	struct cache_node *node, *tmp;
//	HASH_ITER(hh, cache->ht, node, tmp)
//		delete_node(cache, node);
//}

static void
cleanup_test(void)
{
	dl_error = 0;
	cache_commit();
	ck_assert_int_eq(0, system("rm -rf tmp/"));
}

/* Tests */

static const int DOWNLOADED = CNF_RSYNC | CNF_CACHED | CNF_FRESH;
static const int VALIDATED = RSYNC_INHERIT | CNF_VALID;
static const int FULL = DOWNLOADED | VALIDATED;
static const int STALE = CNF_RSYNC | CNF_CACHED | CNF_VALID;
/* Intermediary between a downloaded and a validated node */
static const int BRANCH = RSYNC_INHERIT;
static const int FAILED = CNF_FRESH;

START_TEST(test_cache_download_rsync)
{
	setup_test(false);

	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				uftnode("rsync/a.b.c/d", FULL, "tmp/tmp/0", NULL), NULL), NULL));

	/* Redownload same file, nothing should happen */
	run_dl_rsync("rsync://a.b.c/d", 0, 0);
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				uftnode("rsync/a.b.c/d", FULL, "tmp/tmp/0", NULL), NULL), NULL));

	/*
	 * rsyncs are recursive, which means if we've been recently asked to
	 * download d, we needn't bother redownloading d/e.
	 */
	run_dl_rsync("rsync://a.b.c/d/e", 0, 0);
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				uftnode("rsync/a.b.c/d", FULL, "tmp/tmp/0",
					ufnode("rsync/a.b.c/d/e", VALIDATED, NULL), NULL), NULL), NULL));

	/*
	 * rsyncs get truncated, because it results in much faster
	 * synchronization in practice.
	 * This is not defined in any RFCs; it's an effective standard,
	 * and there would be consequences for violating it.
	 */
	run_dl_rsync("rsync://x.y.z/m/n/o", 0, 1);
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				uftnode("rsync/a.b.c/d", FULL, "tmp/tmp/0",
					ufnode("rsync/a.b.c/d/e", VALIDATED, NULL), NULL), NULL),
			unode("rsync/x.y.z",
				uftnode("rsync/x.y.z/m", DOWNLOADED, "tmp/tmp/1",
					ufnode("rsync/x.y.z/m/n", BRANCH,
						ufnode("rsync/x.y.z/m/n/o", VALIDATED, NULL), NULL), NULL), NULL), NULL));

	/* Sibling */
	run_dl_rsync("rsync://a.b.c/e/f", 0, 1);
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				uftnode("rsync/a.b.c/d", FULL, "tmp/tmp/0",
					ufnode("rsync/a.b.c/d/e", VALIDATED, NULL), NULL),
				uftnode("rsync/a.b.c/e", DOWNLOADED, "tmp/tmp/2",
					ufnode("rsync/a.b.c/e/f", VALIDATED, NULL), NULL), NULL),
			unode("rsync/x.y.z",
				uftnode("rsync/x.y.z/m", DOWNLOADED, "tmp/tmp/1",
					ufnode("rsync/x.y.z/m/n", BRANCH,
						ufnode("rsync/x.y.z/m/n/o", VALIDATED, NULL), NULL), NULL), NULL), NULL));

	cleanup_test();
}
END_TEST

START_TEST(test_cache_download_rsync_error)
{
	setup_test(false);

	dl_error = 0;
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	dl_error = -EINVAL;
	run_dl_rsync("rsync://a.b.c/e", -EINVAL, 1);
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				uftnode("rsync/a.b.c/d", FULL, "tmp/tmp/0", NULL),
				ufnode("rsync/a.b.c/e", FAILED, NULL), NULL), NULL));

	/* Regardless of error, not reattempted because same iteration */
	dl_error = EINVAL;
	run_dl_rsync("rsync://a.b.c/e", -EINVAL, 0);
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				uftnode("rsync/a.b.c/d", FULL, "tmp/tmp/0", NULL),
				ufnode("rsync/a.b.c/e", FAILED, NULL), NULL), NULL));

	dl_error = 0;
	run_dl_rsync("rsync://a.b.c/e", -EINVAL, 0);
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				uftnode("rsync/a.b.c/d", FULL, "tmp/tmp/0", NULL),
				ufnode("rsync/a.b.c/e", FAILED, NULL), NULL), NULL));

	cleanup_test();
}
END_TEST

START_TEST(test_cache_cleanup_rsync)
{
	setup_test(true);

	/*
	 * First iteration: Tree is created. No prunes, because nothing's
	 * outdated.
	 */
	printf("==== First iteration: Tree is created ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				ufnode("rsync/a.b.c/d", FULL, NULL),
				ufnode("rsync/a.b.c/e", FULL, NULL), NULL), NULL));

	/* One iteration with no changes, for paranoia */
	printf("==== No changes, for paranoia ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				ufnode("rsync/a.b.c/d", FULL, NULL),
				ufnode("rsync/a.b.c/e", FULL, NULL), NULL), NULL));

	/* Add one sibling */
	printf("==== Add one sibling ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_dl_rsync("rsync://a.b.c/f", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				ufnode("rsync/a.b.c/d", FULL, NULL),
				ufnode("rsync/a.b.c/e", FULL, NULL),
				ufnode("rsync/a.b.c/f", FULL, NULL), NULL), NULL));

	/* Nodes don't get updated, but they're still too young. */
	printf("==== Still too young ====\n");
	new_iteration(false);
	run_cleanup();
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				ufnode("rsync/a.b.c/d", STALE, NULL),
				ufnode("rsync/a.b.c/e", STALE, NULL),
				ufnode("rsync/a.b.c/f", STALE, NULL), NULL), NULL));

	/* Remove some branches */
	printf("==== Remove some branches ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/d", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				ufnode("rsync/a.b.c/d", FULL, NULL), NULL), NULL));

	/* Remove old branch and add sibling at the same time */
	printf("==== Remove old branch + add sibling ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				ufnode("rsync/a.b.c/e", FULL, NULL), NULL), NULL));

	/* Try child */
	printf("==== Try child ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/e/f/g", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				ufnode("rsync/a.b.c/e", FULL, NULL), NULL), NULL));

	/* Parent again */
	printf("==== Parent again ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_cleanup();
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				ufnode("rsync/a.b.c/e", FULL, NULL), NULL), NULL));

	/* Empty the tree */
	printf("==== Empty the tree ====\n");
	new_iteration(true);
	run_cleanup();
	ck_cache_rsync(unode("rsync", NULL));


	/* Node exists, but file doesn't */
	printf("==== Node exists, but file doesn't ====\n");
	new_iteration(true);
	run_dl_rsync("rsync://a.b.c/e", 0, 1);
	run_dl_rsync("rsync://a.b.c/f", 0, 1);
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				uftnode("rsync/a.b.c/e", FULL, "tmp/tmp/B", NULL),
				uftnode("rsync/a.b.c/f", FULL, "tmp/tmp/C", NULL), NULL), NULL));
	run_cleanup();
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				ufnode("rsync/a.b.c/e", FULL, NULL),
				ufnode("rsync/a.b.c/f", FULL, NULL), NULL), NULL));
	ck_assert_int_eq(0, file_rm_rf("tmp/rsync/a.b.c/f"));
	run_cleanup();
	ck_cache_rsync(
		unode("rsync",
			unode("rsync/a.b.c",
				ufnode("rsync/a.b.c/e", FULL, NULL), NULL), NULL));

	cleanup_test();
}
END_TEST

//START_TEST(test_cache_cleanup_rsync_error)
//{
//	setup_test();
//
//	/* Set up */
//	dl_error = false;
//	run_dl_rsync("rsync://a.b.c/d", 0, 1);
//	dl_error = true;
//	run_dl_rsync("rsync://a.b.c/e", -EINVAL, 1);
//	ck_cache(
//		NODE("rsync://a.b.c/d/", 0, 1, true),
//		NODE("rsync://a.b.c/e/", -EINVAL, 0, false),
//		NULL);
//
//	/* Node gets deleted because cached file doesn't exist */
//	do_cleanup();
//	ck_cache(NODE("rsync://a.b.c/d/", 0, 1, true), NULL);
//
//	/*
//	 * Node and file do not get deleted, because the failure is still not
//	 * that old.
//	 * Deletion does not depend on success or failure.
//	 */
//	new_iteration(false);
//	dl_error = true;
//	run_dl_rsync("rsync://a.b.c/d", -EINVAL, 1);
//	ck_cache(NODE("rsync://a.b.c/d/", -EINVAL, 1, true), NULL);
//
//	/* Error is old; gets deleted */
//	new_iteration(true);
//	do_cleanup();
//	ck_cache(NULL);
//
//	cleanup_test();
//}
//END_TEST
//
//START_TEST(test_cache_download_https)
//{
//	setup_test();
//
//	/* Download *file* e. */
//	run_cache_download("https://a.b.c/d/e", 0, 0, 1);
//	ck_cache(NODE("https://a.b.c/d/e", 0, 1, 1), NULL);
//
//	/* Download something else 1 */
//	run_cache_download("https://a.b.c/e", 0, 0, 1);
//	ck_cache(
//	    NODE("https://a.b.c/d/e", 0, 1, 1),
//	    NODE("https://a.b.c/e", 0, 1, 1),
//	    NULL);
//
//	/* Download something else 2 */
//	run_cache_download("https://x.y.z/e", 0, 0, 1);
//	ck_cache(
//	    NODE("https://a.b.c/d/e", 0, 1, 1),
//	    NODE("https://a.b.c/e", 0, 1, 1),
//	    NODE("https://x.y.z/e", 0, 1, 1),
//	    NULL);
//
//	cleanup_test();
//}
//END_TEST
//
//START_TEST(test_cache_download_https_error)
//{
//	setup_test();
//
//	dl_error = false;
//	run_cache_download("https://a.b.c/d", 0, 0, 1);
//	dl_error = true;
//	run_cache_download("https://a.b.c/e", -EINVAL, 0, 1);
//	ck_cache(
//	    NODE("https://a.b.c/d", 0, 1, 1),
//	    NODE("https://a.b.c/e", -EINVAL, 0, 0),
//	    NULL);
//
//	/* Regardless of error, not reattempted because same iteration */
//	dl_error = true;
//	run_cache_download("https://a.b.c/d", 0, 0, 0);
//	dl_error = false;
//	run_cache_download("https://a.b.c/e", -EINVAL, 0, 0);
//	ck_cache(
//	    NODE("https://a.b.c/d", 0, 1, 1),
//	    NODE("https://a.b.c/e", -EINVAL, 0, 0),
//	    NULL);
//
//	cleanup_test();
//}
//END_TEST
//
//START_TEST(test_cache_cleanup_https)
//{
//	setup_test();
//
//	/* First iteration; make a tree and clean it */
//	new_iteration(true);
//	run_cache_download("https://a.b.c/d", 0, 0, 1);
//	run_cache_download("https://a.b.c/e", 0, 0, 1);
//	do_cleanup();
//	ck_cache(
//		NODE("https://a.b.c/d", 0, 1, 1),
//		NODE("https://a.b.c/e", 0, 1, 1),
//		NULL);
//
//	/* Remove one branch */
//	new_iteration(true);
//	run_cache_download("https://a.b.c/d", 0, 0, 1);
//	do_cleanup();
//	ck_cache(NODE("https://a.b.c/d", 0, 1, 1), NULL);
//
//	/* Change the one branch */
//	new_iteration(true);
//	run_cache_download("https://a.b.c/e", 0, 0, 1);
//	do_cleanup();
//	ck_cache(NODE("https://a.b.c/e", 0, 1, 1), NULL);
//
//	/* Add a child to the same branch, do not update the old one */
//	new_iteration(true);
//	run_cache_download("https://a.b.c/e/f/g", 0, 0, 1);
//	do_cleanup();
//	ck_cache(
//		NODE("https://a.b.c/e/f/g", 0, 1, 1), NULL);
//
//	/*
//	 * Download parent, do not update child.
//	 * Children need to die, because parent is now a file.
//	 */
//	new_iteration(true);
//	run_cache_download("https://a.b.c/e/f", 0, 0, 1);
//	do_cleanup();
//	ck_cache(NODE("https://a.b.c/e/f", 0, 1, 1), NULL);
//
//	/* Do it again. */
//	new_iteration(true);
//	run_cache_download("https://a.b.c/e", 0, 0, 1);
//	do_cleanup();
//	ck_cache(NODE("https://a.b.c/e", 0, 1, 1), NULL);
//
//	/* Empty the tree */
//	new_iteration(true);
//	do_cleanup();
//	ck_cache(NULL);
//
//	/* Node exists, but file doesn't */
//	new_iteration(true);
//	run_cache_download("https://a.b.c/e", 0, 0, 1);
//	run_cache_download("https://a.b.c/f/g/h", 0, 0, 1);
//	ck_cache(
//	    NODE("https://a.b.c/e", 0, 1, 1),
//	    NODE("https://a.b.c/f/g/h", 0, 1, 1),
//	    NULL);
//	ck_assert_int_eq(0, file_rm_rf("tmp/https/a.b.c/f/g/h"));
//	do_cleanup();
//	ck_cache(NODE("https://a.b.c/e", 0, 1, 1), NULL);
//
//	cleanup_test();
//}
//END_TEST
//
//START_TEST(test_cache_cleanup_https_error)
//{
//	setup_test();
//
//	/* Set up */
//	dl_error = false;
//	run_cache_download("https://a.b.c/d", 0, 0, 1);
//	dl_error = true;
//	run_cache_download("https://a.b.c/e", -EINVAL, 0, 1);
//	ck_cache(
//	    NODE("https://a.b.c/d", 0, 1, 1),
//	    NODE("https://a.b.c/e", -EINVAL, 0, 0),
//	    NULL);
//
//	/* Deleted because file ENOENT. */
//	do_cleanup();
//	ck_cache(
//	    NODE("https://a.b.c/d", 0, 1, 1),
//	    NULL);
//
//	/* Fail d */
//	new_iteration(false);
//	dl_error = true;
//	run_cache_download("https://a.b.c/d", -EINVAL, 0, 1);
//	ck_cache(NODE("https://a.b.c/d", -EINVAL, 1, 1), NULL);
//
//	/* Not deleted, because not old */
//	new_iteration(false);
//	do_cleanup();
//	ck_cache(NODE("https://a.b.c/d", -EINVAL, 1, 1), NULL);
//
//	/* Become old */
//	new_iteration(true);
//	do_cleanup();
//	ck_cache(NULL);
//
//	cleanup_test();
//}
//END_TEST
//
//START_TEST(test_dots)
//{
//	setup_test();
//
//	run_cache_download("https://a.b.c/d", 0, 0, 1);
//	ck_cache(NODE("https://a.b.c/d", 0, 1, 1), NULL);
//
//	run_cache_download("https://a.b.c/d/.", 0, 0, 0);
//	ck_cache(NODE("https://a.b.c/d", 0, 1, 1), NULL);
//
//	run_cache_download("https://a.b.c/d/e/..", 0, 0, 0);
//	ck_cache(NODE("https://a.b.c/d", 0, 1, 1), NULL);
//
//	run_cache_download("https://a.b.c/./d/../e", 0, 0, 1);
//	ck_cache(
//	    NODE("https://a.b.c/d", 0, 1, 1),
//	    NODE("https://a.b.c/./d/../e", 0, 1, 1),
//	    NULL);
//
//	cleanup_test();
//}
//END_TEST
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
//
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
//	tcase_add_test(rsync, test_cache_cleanup_rsync_error);

	https = tcase_create("https");
//	tcase_add_test(https, test_cache_download_https);
//	tcase_add_test(https, test_cache_download_https_error);
//	tcase_add_test(https, test_cache_cleanup_https);
//	tcase_add_test(https, test_cache_cleanup_https_error);

	dot = tcase_create("dot");
//	tcase_add_test(dot, test_dots);

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

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
