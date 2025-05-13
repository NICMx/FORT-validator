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
#include "asn1/asn1c/asn_codecs_prim.c"
#include "asn1/asn1c/INTEGER.c"
#include "types/map.c"
#include "types/path.c"
#include "types/str.c"
#include "types/uri.c"

/*
 * XXX
 *
 * Check rpps can't override each other:
 * 	rpp1: rsync://domain/mod/rpp1, file rsync://domain/mod/rpp1/a
 * 	rpp2: rsync://domain/mod/rpp1/a/b, file rsync://domain/mod/rpp1/a/b/c
 * Check nodes are cleaned up when the file doesn't exist
 * Check the file gets cleaned when the node doesn't exist
 * If node is an error, what happens to the refresh and fallback?
 * What happens if the refresh files somehow get deleted before a commit?
 * What happens if the fallback files somehow get deleted before/after a commit?
 */

/* Mocks */

static unsigned int rsync_counter; /* Times the rsync function was called */

static void
touch_file(char const *dir)
{
	char cmd[64];
	ck_assert(snprintf(cmd, sizeof(cmd), "touch %s/file", dir) < sizeof(cmd));
	ck_assert_int_eq(0, system(cmd));
}

static struct uri queued_url;
static char *queued_path;

int
rsync_queue(struct uri const *url, char const *path)
{
	rsync_counter++;

	if (dl_error) {
		printf("Simulating failed rsync.\n");
		return dl_error;
	}

	printf("Simulating rsync: %s -> %s\n", uri_str(url), path);
	ck_assert_int_eq(0, mkdir(path, CACHE_FILEMODE));
	touch_file(path);

	uri_copy(&queued_url, url);
	queued_path = pstrdup(path);

	return 0;
}

MOCK_VOID(__delete_node_cb, struct cache_node const *node)
MOCK_VOID(task_wakeup_dormants, void)
static asn_dec_rval_t dummy = { 0 };
__MOCK_ABORT(ber_check_tags, asn_dec_rval_t, dummy, const asn_codec_ctx_t *ctx,
    const asn_TYPE_descriptor_t *td, asn_struct_ctx_t *opt_ctx,
    const void *ptr, size_t size, int tag_mode, int last_tag_form,
    ber_tlv_len_t *last_length, int *opt_tlv_form)
__MOCK_ABORT(der_write_tags, ssize_t, 0, const asn_TYPE_descriptor_t *sd,
    size_t struct_length, int tag_mode, int last_tag_form, ber_tlv_tag_t tag,
    asn_app_consume_bytes_f *cb, void *app_key)
__MOCK_ABORT(asn__format_to_callback, ssize_t, 0,
    int (*cb)(const void *, size_t, void *key),
    void *key, const char *fmt, ...)
MOCK_ABORT_INT(asn_generic_no_constraint,
    const asn_TYPE_descriptor_t *type_descriptor, const void *struct_ptr,
    asn_app_constraint_failed_f *cb, void *key)

/* Helpers */

static void
setup_test(void)
{
	dl_error = 0;
	init_tables();

	// XXX consider changing this function to `rm -rf <path>/*`
	ck_assert_int_eq(0, file_rm_rf("."));
	ck_assert_int_eq(0, mkdir("rsync", CACHE_FILEMODE));
	ck_assert_int_eq(0, mkdir("https", CACHE_FILEMODE));
	ck_assert_int_eq(0, mkdir("rrdp", CACHE_FILEMODE));
	ck_assert_int_eq(0, mkdir("fallback", CACHE_FILEMODE));
	ck_assert_int_eq(0, mkdir("tmp", CACHE_FILEMODE));
}

static struct cache_cage *
run_dl_rsync(char *caRepository, validation_verdict vv,
    unsigned int expected_calls)
{
	struct sia_uris sias = { 0 };
	struct cache_cage *cage;

	ck_assert_ptr_eq(NULL, uri_init(&sias.caRepository, caRepository));
	cage = NULL;

	rsync_counter = 0;
	https_counter = 0;
	printf("---- Downloading... ----\n");
	ck_assert_str_eq(vv, cache_refresh_by_sias(&sias, &cage));
	printf("---- Downloaded. ----\n");
	ck_assert_uint_eq(expected_calls, rsync_counter);
	ck_assert_uint_eq(0, https_counter);

	uri_cleanup(&sias.caRepository);
	return cage;
}

static void
finish_rsync(void)
{
	rsync_finished(&queued_url, queued_path);
	uri_cleanup(&queued_url);
	free(queued_path);
}

static struct cache_cage *
rsync_dance(char *url)
{
	ck_assert_ptr_eq(NULL, run_dl_rsync(url, VV_BUSY, 1));
	finish_rsync();
	return run_dl_rsync(url, VV_CONTINUE, 0);
}

static void
run_dl_https(char const *url, unsigned int expected_calls,
    char const *expected_result)
{
	struct uri uri;
	char const *result;

	ck_assert_ptr_eq(NULL, uri_init(&uri, url));

	rsync_counter = 0;
	https_counter = 0;
	printf("---- Downloading... ----\n");
	result = cache_refresh_by_url(&uri);
	printf("---- Downloaded. ----\n");
	ck_assert_uint_eq(0, rsync_counter);
	ck_assert_uint_eq(expected_calls, https_counter);

	ck_assert_str(expected_result, result);
	ck_assert_str(NULL, cache_get_fallback(&uri));

	uri_cleanup(&uri);
}


static void
ck_cage(struct cache_cage *cage, char const *url,
    char const *refresh, char const *fallback)
{
	struct uri uri;
	struct cache_node const *bkp;

	ck_assert_ptr_eq(NULL, uri_init(&uri, url));

	ck_assert_str(refresh, cage_map_file(cage, &uri));

	bkp = cage->refresh;
	cage_disable_refresh(cage);
	ck_assert_str(fallback, cage_map_file(cage, &uri));
	cage->refresh = bkp;

	uri_cleanup(&uri);
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
	ck_assert_int_eq(0, nftw(".", print_file, 32, FTW_PHYS));
	printf("\n");
}

static void
queue_commit(char const *rpkiNotify, char const *caRepository,
    char const *path1, char const *path2)
{
	struct rpp rpp = { 0 };
	struct uri rn, cr;

	if (rpkiNotify)
		ck_assert_ptr_eq(NULL, uri_init(&rn, rpkiNotify));
	else
		memset(&rn, 0, sizeof(rn));
	if (caRepository)
		ck_assert_ptr_eq(NULL, uri_init(&cr, caRepository));
	else
		memset(&cr, 0, sizeof(cr));

	rpp.nfiles = 2;
	rpp.files = pzalloc(rpp.nfiles * sizeof(struct cache_mapping));
	URI_CHILD(&cr, "manifest.mft", &rpp.files[0].url);
	rpp.files[0].path = pstrdup(path1);
	URI_CHILD(&cr, "cert.cer", &rpp.files[1].url);
	rpp.files[1].path = pstrdup(path2);

	cache_commit_rpp(&rn, &cr, &rpp);

	uri_cleanup(&cr);
	uri_cleanup(&rn);
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
    int fresh, validation_verdict vv)
{
	node->key.id = url;
	node->key.idlen = strlen(url);
	ck_assert_ptr_eq(NULL, uri_init(&node->key.rsync, url));
	node->path = path;
	node->state = fresh ? DLS_FRESH : DLS_OUTDATED; /* XXX (test) */
	node->verdict = vv;
	node->rrdp = NULL;
}

static void
init_node_https(struct cache_node *node, char *url, char *path,
    int fresh, validation_verdict vv)
{
	node->key.id = url;
	node->key.idlen = strlen(url);
	ck_assert_ptr_eq(NULL, uri_init(&node->key.http, url));
	node->path = path;
	node->state = fresh ? DLS_FRESH : DLS_OUTDATED;
	node->verdict = vv;
	node->rrdp = NULL;
}

static void
ck_node_key(struct node_key *expected, struct node_key *actual)
{
	ck_assert(uri_equals(&expected->http, &actual->http));
	ck_assert(uri_equals(&expected->rsync, &actual->rsync));
	ck_assert_uint_eq(expected->idlen, actual->idlen);
	ck_assert_mem_eq(expected->id, actual->id, expected->idlen);
}

static void
ck_cache_node_eq(struct cache_node *expected, struct cache_node *actual)
{
	ck_node_key(&expected->key, &actual->key);
	ck_assert_str_eq(expected->path, actual->path);
	ck_assert_int_eq(expected->state, actual->state);
	ck_assert_str_eq(expected->verdict, actual->verdict);
	if (expected->rrdp == NULL)
		ck_assert_ptr_eq(expected->rrdp, actual->rrdp);
	// XXX else
}

static void
ck_cache(struct cache_node *expecteds, struct cache_table *tbl)
{
	struct cache_node *actual, *tmp;
	unsigned int n;

	for (n = 0; expecteds[n].key.id != NULL; n++)
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
unfreshen(struct cache_table *tbl, struct cache_node *node, void *arg)
{
	node->state = DLS_OUTDATED;
	node->attempt_ts -= 4;
	node->attempt_ts -= 4;
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
	foreach_node(unfreshen, NULL);
	ck_assert_int_eq(0, nftw(".", nftw_unfreshen, 32, FTW_PHYS));

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
	cage = rsync_dance("rsync://a.b.c/d");
	ck_assert_ptr_ne(NULL, cage);
	ck_cage(cage, "rsync://a.b.c/d", "rsync/0", NULL);
	ck_cage(cage, "rsync://a.b.c/d/e/f.cer", "rsync/0/e/f.cer", NULL);
	init_node_rsync(&nodes[0], "rsync://a.b.c/d", "rsync/0", 1, VV_CONTINUE);
	ck_cache_rsync(nodes);
	free(cage);

	printf("==== Redownload same file, nothing should happen ====\n");
	cage = run_dl_rsync("rsync://a.b.c/d", VV_CONTINUE, 0);
	ck_assert_ptr_ne(NULL, cage);
	ck_cage(cage, "rsync://a.b.c/d", "rsync/0", NULL);
	ck_cage(cage, "rsync://a.b.c/d/e/f.cer", "rsync/0/e/f.cer", NULL);
	ck_cache_rsync(nodes);
	free(cage);

	/*
	 * rsyncs are recursive, which means if we've been recently asked to
	 * download d, we needn't bother redownloading d/e.
	 */
	printf("==== Don't redownload child ====\n");
	cage = run_dl_rsync("rsync://a.b.c/d/e", VV_CONTINUE, 0);
	ck_assert_ptr_ne(NULL, cage);
	ck_cage(cage, "rsync://a.b.c/d", "rsync/0", NULL);
	ck_cage(cage, "rsync://a.b.c/d/e/f.cer", "rsync/0/e/f.cer", NULL);
	ck_cache_rsync(nodes);
	free(cage);

	/*
	 * rsyncs get truncated, because it results in much faster
	 * synchronization in practice.
	 * This is not defined in any RFCs; it's an effective standard,
	 * and there would be consequences for violating it.
	 */
	printf("==== rsync truncated ====\n");
	cage = rsync_dance("rsync://x.y.z/m/n/o");
	ck_assert_ptr_ne(NULL, cage);
	ck_cage(cage, "rsync://x.y.z/m", "rsync/1", NULL);
	ck_cage(cage, "rsync://x.y.z/m/n/o", "rsync/1/n/o", NULL);
	init_node_rsync(&nodes[1], "rsync://x.y.z/m", "rsync/1", 1, VV_CONTINUE);
	ck_cache_rsync(nodes);
	free(cage);

	printf("==== Sibling ====\n");
	cage = rsync_dance("rsync://a.b.c/e/f");
	ck_assert_ptr_ne(NULL, cage);
	ck_cage(cage, "rsync://a.b.c/e", "rsync/2", NULL);
	ck_cage(cage, "rsync://a.b.c/e/f/x/y/z", "rsync/2/f/x/y/z", NULL);
	init_node_rsync(&nodes[2], "rsync://a.b.c/e", "rsync/2", 1, VV_CONTINUE);
	ck_cache_rsync(nodes);
	free(cage);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_download_rsync_error)
{
	struct cache_node nodes[3] = { 0 };

	setup_test();

	init_node_rsync(&nodes[0], "rsync://a.b.c/d", "rsync/0", 1, VV_CONTINUE);
	init_node_rsync(&nodes[1], "rsync://a.b.c/e", "rsync/1", 1, VV_FAIL);

	printf("==== Startup ====\n");
	dl_error = 0;
	free(rsync_dance("rsync://a.b.c/d"));
	dl_error = EINVAL;
	ck_assert_ptr_eq(NULL, run_dl_rsync("rsync://a.b.c/e", VV_FAIL, 1));
	ck_cache_rsync(nodes);

	printf("==== Regardless of error, not reattempted because same iteration ====\n");
	dl_error = EINVAL;
	ck_assert_ptr_eq(NULL, run_dl_rsync("rsync://a.b.c/e", VV_FAIL, 0));
	ck_cache_rsync(nodes);
	dl_error = 0;
	ck_assert_ptr_eq(NULL, run_dl_rsync("rsync://a.b.c/e", VV_FAIL, 0));
	ck_cache_rsync(nodes);

	cleanup_test();
}
END_TEST

START_TEST(test_rsync_cleanup)
{
	unsigned int i;

	setup_test();

	ck_assert_int_eq(0, mkdir("rsync/0", CACHE_FILEMODE));
	ck_assert_int_eq(0, mkdir("rsync/1", CACHE_FILEMODE));
	ck_assert_int_eq(0, mkdir("rsync/2", CACHE_FILEMODE));
	ck_assert_int_eq(0, mkdir("rsync/3", CACHE_FILEMODE));

	/* RPP0: Will remain constant */
	ck_assert_int_eq(0, file_write_txt("rsync/0/0", "A"));
	ck_assert_int_eq(0, file_write_txt("rsync/0/1", "B"));
	/* RPP1: Will be added in its second cycle */
	ck_assert_int_eq(0, file_write_txt("rsync/1/0", "C"));
	ck_assert_int_eq(0, file_write_txt("rsync/1/1", "D"));
	/* RPP2: Will be removed in its second cycle */
	ck_assert_int_eq(0, file_write_txt("rsync/2/0", "E"));
	ck_assert_int_eq(0, file_write_txt("rsync/2/1", "F"));
	/* RPP3: Will be updated in its second cycle */
	ck_assert_int_eq(0, file_write_txt("rsync/3/0", "G")); /* Keeper */
	ck_assert_int_eq(0, file_write_txt("rsync/3/1", "H")); /* Added */
	ck_assert_int_eq(0, file_write_txt("rsync/3/2", "I")); /* Removed */

	/* Commit 1: Empty -> Empty */
	/* Commit 2: Empty -> Empty (just free noise) */
	for (i = 0; i < 2; i++) {
		cleanup_cache();
		ck_filesystem("fallback", NULL);

		new_iteration(false);
	}

	/* Commit 3: Empty -> Populated */
	queue_commit(NULL, "rsync://domain/mod/rpp0", "rsync/0/0", "rsync/0/1");
	queue_commit(NULL, "rsync://domain/mod/rpp2", "rsync/2/0", "rsync/2/1");
	queue_commit(NULL, "rsync://domain/mod/rpp3", "rsync/3/0", "rsync/3/2");
	cleanup_cache();
	ck_filesystem("fallback",
	    /* RPP0 */ "fallback/0/0", "A", "fallback/0/1", "B", "fallback/0.json", "{",
	    /* RPP2 */ "fallback/1/0", "E", "fallback/1/1", "F", "fallback/1.json", "{",
	    /* RPP3 */ "fallback/2/0", "G", "fallback/2/1", "I", "fallback/2.json", "{",
	    NULL);

	new_iteration(false);

	/* Commit 4: Populated -> Populated */
	/* XXX check the refresh does, in fact, only return fallbacks when the RPP doesn't change */
	queue_commit(NULL, "rsync://domain/mod/rpp0", "fallback/0/0", "fallback/0/1");
	queue_commit(NULL, "rsync://domain/mod/rpp1", "rsync/1/0", "rsync/1/1");
	queue_commit(NULL, "rsync://domain/mod/rpp3", "fallback/2/0", "rsync/3/1");
	cleanup_cache();

	ck_filesystem("fallback",
	    /* RPP0 */ "fallback/0/0", "A", "fallback/0/1", "B", "fallback/0.json", "{",
	    /* RPP3 */ "fallback/2/0", "G", "fallback/2/2", "H", "fallback/2.json", "{",
	    /* RPP1 */ "fallback/3/0", "C", "fallback/3/1", "D", "fallback/3.json", "{",
	    NULL);

	new_iteration(false);

	/* Commit 5: Populated -> Empty */
	cleanup_cache();
	ck_filesystem("fallback", NULL);

	flush_nodes();
}
END_TEST

START_TEST(test_cache_download_https)
{
	struct cache_node nodes[4] = { 0 };

	setup_test();

	printf("==== Download file ====\n");
	run_dl_https("https://a.b.c/d/e", 1, "https/0");
	init_node_https(&nodes[0], "https://a.b.c/d/e", "https/0", 1, VV_CONTINUE);
	ck_cache_https(nodes);

	printf("==== Download same file ====\n");
	run_dl_https("https://a.b.c/d/e", 0, "https/0");
	ck_cache_https(nodes);

	printf("==== Download something else 1 ====\n");
	run_dl_https("https://a.b.c/e", 1, "https/1");
	init_node_https(&nodes[1], "https://a.b.c/e", "https/1", 1, VV_CONTINUE);
	ck_cache_https(nodes);

	printf("==== Download something else 2 ====\n");
	run_dl_https("https://x.y.z/e", 1, "https/2");
	init_node_https(&nodes[2], "https://x.y.z/e", "https/2", 1, VV_CONTINUE);
	ck_cache_https(nodes);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_download_https_error)
{
	struct cache_node nodes[3] = { 0 };

	setup_test();

	init_node_https(&nodes[0], "https://a.b.c/d", "https/0", 1, VV_CONTINUE);
	init_node_https(&nodes[1], "https://a.b.c/e", "https/1", 1, VV_FAIL);

	printf("==== Startup ====\n");
	dl_error = 0;
	run_dl_https("https://a.b.c/d", 1, "https/0");
	dl_error = EINVAL;
	run_dl_https("https://a.b.c/e", 1, NULL);
	ck_cache_https(nodes);

	printf("==== Regardless of error, not reattempted because same iteration ====\n");
	dl_error = EINVAL;
	run_dl_https("https://a.b.c/d", 0, "https/0");
	run_dl_https("https://a.b.c/e", 0, NULL);
	dl_error = 0;
	run_dl_https("https://a.b.c/d", 0, "https/0");
	run_dl_https("https://a.b.c/e", 0, NULL);
	ck_cache_https(nodes);

	cleanup_test();
}
END_TEST

/* See comments at test_rsync_cleanup(). */
START_TEST(test_https_cleanup)
{
	struct cache_mapping map;
	unsigned int i;

	setup_test();

	ck_assert_int_eq(0, file_write_txt("https/50", "A")); /* Keeper */
	ck_assert_int_eq(0, file_write_txt("https/51", "B")); /* Added */
	ck_assert_int_eq(0, file_write_txt("https/52", "C")); /* Removed */

	/* 1, 2 */
	for (i = 0; i < 2; i++) {
		cleanup_cache();
		ck_filesystem("fallback", NULL);

		new_iteration(false);
	}

	/* 3 */
	ck_assert_ptr_eq(NULL, uri_init(&map.url, "https://domain/rpki/ta50.cer"));
	map.path = pstrdup("https/50");
	cache_commit_file(&map);
	map_cleanup(&map);

	ck_assert_ptr_eq(NULL, uri_init(&map.url, "https://domain/rpki/ta52.cer"));
	map.path = pstrdup("https/52");
	cache_commit_file(&map);
	map_cleanup(&map);

	cleanup_cache();
	ck_filesystem("fallback",
	    "fallback/0", "A", "fallback/0.json", "{",
	    "fallback/1", "C", "fallback/1.json", "{",
	    NULL);

	new_iteration(false);

	/* 4 */
	ck_assert_ptr_eq(NULL, uri_init(&map.url, "https://domain/rpki/ta50.cer"));
	map.path = pstrdup("fallback/0");
	cache_commit_file(&map);
	map_cleanup(&map);

	ck_assert_ptr_eq(NULL, uri_init(&map.url, "https://domain/rpki/ta51.cer"));
	map.path = pstrdup("https/51");
	cache_commit_file(&map);
	map_cleanup(&map);

	cleanup_cache();
	ck_filesystem("fallback",
	    "fallback/0", "A", "fallback/0.json", "{",
	    "fallback/2", "B", "fallback/2.json", "{",
	    NULL);

	new_iteration(false);

	/* 5 */
	cleanup_cache();
	ck_filesystem("fallback", NULL);

	flush_nodes();
}
END_TEST

/* See comments at test_rsync_cleanup(). */
START_TEST(test_rrdp_cleanup)
{
	char const *notif = "https://domain/rpki/notif.xml";
	unsigned int i;

	setup_test();

	ck_assert_int_eq(0, mkdir("rrdp/0", CACHE_FILEMODE));
	ck_assert_int_eq(0, mkdir("rrdp/1", CACHE_FILEMODE));
	ck_assert_int_eq(0, mkdir("rrdp/2", CACHE_FILEMODE));
	ck_assert_int_eq(0, mkdir("rrdp/3", CACHE_FILEMODE));

	ck_assert_int_eq(0, file_write_txt("rrdp/0/0", "A"));
	ck_assert_int_eq(0, file_write_txt("rrdp/0/1", "B"));
	ck_assert_int_eq(0, file_write_txt("rrdp/1/0", "C"));
	ck_assert_int_eq(0, file_write_txt("rrdp/1/1", "D"));
	ck_assert_int_eq(0, file_write_txt("rrdp/2/0", "E"));
	ck_assert_int_eq(0, file_write_txt("rrdp/2/1", "F"));
	ck_assert_int_eq(0, file_write_txt("rrdp/3/0", "G"));
	ck_assert_int_eq(0, file_write_txt("rrdp/3/1", "H"));
	ck_assert_int_eq(0, file_write_txt("rrdp/3/2", "I"));

	/* 1, 2 */
	for (i = 0; i < 2; i++) {
		cleanup_cache();
		ck_filesystem("fallback", NULL);

		new_iteration(false);
	}

	/* 3 */
	queue_commit(notif, "rsync://domain/mod/rpp0", "rrdp/0/0", "rrdp/0/1");
	queue_commit(notif, "rsync://domain/mod/rpp2", "rrdp/2/0", "rrdp/2/1");
	queue_commit(notif, "rsync://domain/mod/rpp3", "rrdp/3/0", "rrdp/3/2");
	cleanup_cache();
	ck_filesystem("fallback",
	    "fallback/0/0", "A", "fallback/0/1", "B", "fallback/0.json", "{",
	    "fallback/1/0", "E", "fallback/1/1", "F", "fallback/1.json", "{",
	    "fallback/2/0", "G", "fallback/2/1", "I", "fallback/2.json", "{",
	    NULL);

	new_iteration(false);

	/* 4 */
	queue_commit(notif, "rsync://domain/mod/rpp0", "fallback/0/0", "fallback/0/1");
	queue_commit(notif, "rsync://domain/mod/rpp1", "rrdp/1/0", "rrdp/1/1");
	queue_commit(notif, "rsync://domain/mod/rpp3", "fallback/2/0", "rrdp/3/1");
	cleanup_cache();
	ck_filesystem("fallback",
	    "fallback/0/0", "A", "fallback/0/1", "B", "fallback/0.json", "{",
	    "fallback/2/0", "G", "fallback/2/2", "H", "fallback/2.json", "{",
	    "fallback/3/0", "C", "fallback/3/1", "D", "fallback/3.json", "{",
	    NULL);

	new_iteration(false);

	/* 5 */
	cleanup_cache();
	ck_filesystem("fallback", NULL);

	flush_nodes();
}
END_TEST

START_TEST(test_context)
{
	char *RPKI_NOTIFY =	"https://a.b.c/notif.xml";
	char *CA_REPOSITORY =	"rsync://x.y.z/mod5/rpp3";
	char *FILE_URL =	"rsync://x.y.z/mod5/rpp3/a.cer";
	char *FILE_RRDP_PATH =	"rrdp/0/0";
	char *FILE_RSYNC_PATH =	"rsync/0/rpp3/a.cer";

	struct sia_uris sias = { 0 };
	struct uri file_url;
	struct cache_cage *cage;
	struct rpp rpp = { 0 };

	ck_assert_int_eq(0, hash_setup());
	ck_assert_int_eq(0, relax_ng_init());
	setup_test();

	dls[0] = NHDR("3")
		NSS("https://a.b.c/3/snapshot.xml",
		    "25b49ae65eeeda44222d599959086911c65ed4277021cdec456d80a6604b83c9")
		NTAIL;
	dls[1] = SHDR("3") PBLSH("rsync://x.y.z/mod5/rpp3/a.cer", "Rm9ydAo=") STAIL;
	dls[2] = NULL;

	ck_assert_ptr_eq(NULL, uri_init(&file_url, FILE_URL));

	printf("1. 1st CA succeeds on RRDP\n");
	print_tree();
	ck_assert_ptr_eq(NULL, uri_init(&sias.rpkiNotify, RPKI_NOTIFY));
	ck_assert_ptr_eq(NULL, uri_init(&sias.caRepository, CA_REPOSITORY));
	ck_assert_str_eq(VV_CONTINUE, cache_refresh_by_sias(&sias, &cage));
	ck_assert_str_eq(RPKI_NOTIFY, uri_str(&cage->rpkiNotify));
	ck_assert_str_eq(FILE_RRDP_PATH, cage_map_file(cage, &file_url));
	ck_assert_int_eq(false, cage_disable_refresh(cage));
	ck_assert_ptr_eq(NULL, cage_map_file(cage, &file_url));

	printf("2. 2nd CA points to the same caRepository,\n");
	printf("   but does not provide RRDP as an option.\n");
	print_tree();
	uri_cleanup(&sias.rpkiNotify);

	ck_assert_str_eq(VV_BUSY, cache_refresh_by_sias(&sias, &cage));
	finish_rsync();
	ck_assert_str_eq(VV_CONTINUE, cache_refresh_by_sias(&sias, &cage));

	ck_assert_ptr_eq(NULL, uri_str(&cage->rpkiNotify));
	ck_assert_str_eq(FILE_RSYNC_PATH, cage_map_file(cage, &file_url));
	ck_assert_int_eq(false, cage_disable_refresh(cage));
	ck_assert_ptr_eq(NULL, cage_map_file(cage, &file_url));

	printf("3. Commit\n");

	print_tree();
	rpp.nfiles = 1;
	rpp.files = pzalloc(sizeof(struct cache_mapping));
	uri_copy(&rpp.files->url, &file_url);
	rpp.files->path = pstrdup(FILE_RRDP_PATH);
	ck_assert_ptr_eq(NULL, uri_init(&sias.rpkiNotify, RPKI_NOTIFY));
	cache_commit_rpp(&sias.rpkiNotify, &sias.caRepository, &rpp);

	rpp.nfiles = 1;
	rpp.files = pzalloc(sizeof(struct cache_mapping));
	uri_copy(&rpp.files->url, &file_url);
	rpp.files->path = pstrdup(FILE_RSYNC_PATH);
	uri_cleanup(&sias.rpkiNotify);
	cache_commit_rpp(&sias.rpkiNotify, &sias.caRepository, &rpp);

	commit_fallbacks(time_fatal());

	printf("4. Redo both CAs, check the fallbacks too\n");
	print_tree();
	ck_assert_str_eq(VV_CONTINUE, cache_refresh_by_sias(&sias, &cage));
	ck_assert_ptr_eq(NULL, uri_str(&cage->rpkiNotify));
	ck_assert_str_eq(FILE_RSYNC_PATH, cage_map_file(cage, &file_url));
	ck_assert_int_eq(true, cage_disable_refresh(cage));
	ck_assert_str_eq("fallback/1/0", cage_map_file(cage, &file_url));

	ck_assert_ptr_eq(NULL, uri_init(&sias.rpkiNotify, RPKI_NOTIFY));
	ck_assert_str_eq(VV_CONTINUE, cache_refresh_by_sias(&sias, &cage));
	ck_assert_str_eq(RPKI_NOTIFY, uri_str(&cage->rpkiNotify));
	ck_assert_str_eq(FILE_RRDP_PATH, cage_map_file(cage, &file_url));
	ck_assert_int_eq(true, cage_disable_refresh(cage));
	ck_assert_str_eq("fallback/0/0", cage_map_file(cage, &file_url));

	uri_cleanup(&sias.rpkiNotify);
	uri_cleanup(&sias.caRepository);
	uri_cleanup(&file_url);

	cleanup_test();
	relax_ng_cleanup();
	hash_teardown();
}
END_TEST

static void
ck_rrdp(struct rrdp_state *expected, struct rrdp_state *actual)
{
	struct cache_file *expf, *actf, *tmp;
	struct rrdp_hash *exph, *acth;

	if (expected == NULL) {
		ck_assert_ptr_eq(NULL, actual);
		return;
	}

	ck_assert_ptr_ne(NULL, actual);
	ck_assert_str_eq(expected->session.session_id, actual->session.session_id);
	ck_assert_int_eq(0, BN_cmp(expected->session.serial.num, actual->session.serial.num));
	ck_assert_str_eq(expected->session.serial.str, actual->session.serial.str);

	ck_assert_int_eq(HASH_COUNT(expected->files), HASH_COUNT(actual->files));
	HASH_ITER(hh, expected->files, expf, tmp) {
		HASH_FIND(hh, actual->files, uri_str(&expf->map.url), uri_len(&expf->map.url), actf);
		ck_assert_ptr_ne(NULL, actf);
		ck_assert(uri_equals(&expf->map.url, &actf->map.url));
		ck_assert_str_eq(expf->map.path, actf->map.path);
	}

	acth = STAILQ_FIRST(&expected->delta_hashes);
	STAILQ_FOREACH(exph, &expected->delta_hashes, hook) {
		ck_assert_ptr_ne(NULL, acth);
		ck_assert(memcmp(exph->bytes, acth->bytes, sizeof(exph->bytes)) == 0);
		acth = STAILQ_NEXT(acth, hook);
	}
	ck_assert_ptr_eq(NULL, acth);
}

static void
ck_json(struct cache_node *src)
{
	struct cache_node *dst;
	json_t *json;

	json = node2json(src);
	json_dumpf(json, stdout, JSON_INDENT(2));
	printf("\n");
	ck_assert_ptr_ne(NULL, json);
	dst = json2node(json);
	json_decref(json);

	ck_node_key(&src->key, &dst->key);
	ck_assert_str_eq(src->path, dst->path);
	ck_assert_int_eq(DLS_OUTDATED, dst->state);	/* Must be reset */
	ck_assert_ptr_eq(NULL, dst->verdict);		/* Must be reset */
	ck_assert_int_eq(src->attempt_ts, dst->attempt_ts);
	ck_assert_int_eq(src->success_ts, dst->success_ts);
	ck_assert(INTEGER_cmp(&src->mft.num, &dst->mft.num) == 0);
	ck_assert_int_eq(src->mft.update, dst->mft.update);
	ck_rrdp(src->rrdp, dst->rrdp);

	delete_node(NULL, src, NULL);
	delete_node(NULL, dst, NULL);
}

START_TEST(test_json_min)
{
	struct cache_node *node = pzalloc(sizeof(struct cache_node));

	node->key.id = pstrdup("https://a.b.c/sample.cer");
	node->key.idlen = strlen(node->key.id);
	__uri_init(&node->key.http, node->key.id, node->key.idlen);
	node->path = pstrdup("tmp/sample.cer");
	node->state = DLS_FRESH;
	node->verdict = VV_FAIL;

	ck_json(node);
}

static void
CACHE_FILE_ADD(struct rrdp_state *state, char const *url, char *path)
{
	struct uri uri;

	ck_assert_ptr_eq(NULL, uri_init(&uri, url));
	ck_assert_ptr_ne(NULL, cache_file_add(state, &uri, pstrdup(path)));
	uri_cleanup(&uri);
}

START_TEST(test_json_rrdp_min)
{
	struct cache_node *node = pzalloc(sizeof(struct cache_node));

	node->key.id = pstrdup("https://a.b.c/sample.cer");
	node->key.idlen = strlen(node->key.id);
	__uri_init(&node->key.http, node->key.id, node->key.idlen);
	node->path = pstrdup("rrdp/123");
	node->state = DLS_FRESH;
	node->verdict = VV_FAIL;

	node->rrdp = pmalloc(sizeof(struct rrdp_state));
	node->rrdp->session.session_id = pstrdup("session");
	node->rrdp->session.serial.num = BN_create();
	ck_assert_ptr_ne(NULL, node->rrdp->session.serial.num);
	BN_add_word(node->rrdp->session.serial.num, 1357);
	node->rrdp->session.serial.str = pstrdup("1357");
	CACHE_FILE_ADD(node->rrdp, "rsync://a.b.c/d/e.mft", "rrdp/123/0");
	cseq_init(&node->rrdp->seq, node->path, 1, false);
	STAILQ_INIT(&node->rrdp->delta_hashes);

	ck_json(node);
}

START_TEST(test_json_max)
{
	struct cache_node *node = pzalloc(sizeof(struct cache_node));
	struct rrdp_hash *hash;

	node->key.id = pstrdup("https://a.b.c/sample.cer");
	node->key.idlen = strlen(node->key.id);
	__uri_init(&node->key.http, node->key.id, node->key.idlen);
	node->path = pstrdup("rrdp/123");
	node->state = DLS_FRESH;
	node->verdict = VV_FAIL;
	node->attempt_ts = 1234;
	node->success_ts = 4321;
	ck_assert_int_eq(0, asn_long2INTEGER(&node->mft.num, 5678));
	node->mft.update = 8765;

	node->rrdp = pmalloc(sizeof(struct rrdp_state));
	node->rrdp->session.session_id = pstrdup("session");
	node->rrdp->session.serial.num = BN_create();
	ck_assert_ptr_ne(NULL, node->rrdp->session.serial.num);
	BN_add_word(node->rrdp->session.serial.num, 1357);
	node->rrdp->session.serial.str = pstrdup("1357");
	CACHE_FILE_ADD(node->rrdp, "rsync://a.b.c/d/e.mft", "rrdp/123/0");
	CACHE_FILE_ADD(node->rrdp, "rsync://a.b.c/d/f.crl", "rrdp/123/1");
	cseq_init(&node->rrdp->seq, node->path, 2, false);
	STAILQ_INIT(&node->rrdp->delta_hashes);
	hash = pmalloc(sizeof(struct rrdp_hash));
	memset(&hash->bytes, 1, sizeof(hash->bytes));
	STAILQ_INSERT_HEAD(&node->rrdp->delta_hashes, hash, hook);
	hash = pmalloc(sizeof(struct rrdp_hash));
	memset(&hash->bytes, 2, sizeof(hash->bytes));
	STAILQ_INSERT_HEAD(&node->rrdp->delta_hashes, hash, hook);

	ck_json(node);
}

START_TEST(test_json_weirdurl)
{
	static char const *NOTIF = "https://a.b.c/notif.xml";
	static char const *CAREPO = "rsync://a.b.c/rpp";
	size_t nlen;
	size_t clen;
	struct cache_node *node;

	nlen = strlen(NOTIF);
	clen = strlen(CAREPO);
	node = pzalloc(sizeof(struct cache_node));

	node->key.idlen = nlen + clen + 1;
	node->key.id = pmalloc(node->key.idlen + 1);
	strcpy(node->key.id, NOTIF);
	strcpy(node->key.id + nlen + 1, CAREPO);
	__uri_init(&node->key.http, node->key.id, nlen);
	__uri_init(&node->key.rsync, node->key.id + nlen + 1, clen);
	node->path = pstrdup("tmp/sample.cer");
	node->state = DLS_FRESH;
	node->verdict = VV_FAIL;
	node->attempt_ts = 1234;
	node->success_ts = 4321;
	ck_assert_int_eq(0, asn_long2INTEGER(&node->mft.num, 5678));
	node->mft.update = 8765;

	ck_json(node);
}

/* Boilerplate */

static Suite *create_suite(void)
{
	Suite *suite;
	TCase *rsync, *https, *rrdp, *multi, *json;

	rsync = tcase_create("rsync");
	tcase_add_test(rsync, test_cache_download_rsync);
	tcase_add_test(rsync, test_cache_download_rsync_error);
	tcase_add_test(rsync, test_rsync_cleanup);

	https = tcase_create("https");
	tcase_add_test(https, test_cache_download_https);
	tcase_add_test(https, test_cache_download_https_error);
	tcase_add_test(https, test_https_cleanup);

	rrdp = tcase_create("rrdp");
	tcase_add_test(rrdp, test_rrdp_cleanup);

	multi = tcase_create("multi-protocol");
	tcase_add_test(multi, test_context);

	json = tcase_create("json");
	tcase_add_test(json, test_json_min);
	tcase_add_test(json, test_json_rrdp_min);
	tcase_add_test(json, test_json_max);
	tcase_add_test(json, test_json_weirdurl);

	suite = suite_create("local-cache");
	suite_add_tcase(suite, rsync);
	suite_add_tcase(suite, https);
	suite_add_tcase(suite, rrdp);
	suite_add_tcase(suite, multi);
	suite_add_tcase(suite, json);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	dls[0] = "Fort\n";

	if (mkdir("tmp", CACHE_FILEMODE) < 0 && errno != EEXIST) {
		fprintf(stderr, "mkdir('tmp/'): %s\n", strerror(errno));
		return 1;
	}
	if (mkdir("tmp/cache", CACHE_FILEMODE) < 0 && errno != EEXIST) {
		fprintf(stderr, "mkdir('tmp/cache'): %s\n", strerror(errno));
		return 1;
	}
	if (chdir("tmp/cache") < 0) {
		fprintf(stderr, "chdir('tmp/cache'): %s\n", strerror(errno));
		return 1;
	}

	suite = create_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
