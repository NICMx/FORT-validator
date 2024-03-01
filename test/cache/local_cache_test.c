/* This test will create temporal directory "tmp/". Needs permissions. */

#include "cache/local_cache.c"

#include <check.h>
#include <stdarg.h>
#include <sys/queue.h>

#include "alloc.c"
#include "common.c"
#include "json_util.c"
#include "mock.c"
#include "data_structure/path_builder.c"
#include "types/uri.c"

/* Mocks */

#define TAL_FILE "test.tal"

static struct rpki_cache *cache;

static bool dl_error; /* Download should return error? */

struct downloaded_path {
	char *path;
	bool visited;
	SLIST_ENTRY(downloaded_path) hook;
};

/* Paths downloaded during the test */
static SLIST_HEAD(downloaded_paths, downloaded_path) downloaded;

static unsigned int rsync_counter; /* Times the rsync function was called */
static unsigned int https_counter; /* Times the https function was called */

int
file_exists(char const *file)
{
	struct downloaded_path *path;
	SLIST_FOREACH(path, &downloaded, hook)
		if (strcmp(file, path->path) == 0)
			return 0;
	return ENOENT;
}

int
file_rm_rf(char const *file)
{
	struct downloaded_path *path;
	SLIST_FOREACH(path, &downloaded, hook)
		if (strcmp(file, path->path) == 0) {
			SLIST_REMOVE(&downloaded, path, downloaded_path, hook);
			free(path->path);
			free(path);
			return 0;
		}
	return ENOENT;
}

int
file_rm_f(char const *file)
{
	file_rm_rf(file);
	return 0;
}

MOCK_ABORT_INT(file_get_mtim, char const *file, time_t *ims)

static int
pretend_download(struct rpki_uri *uri)
{
	struct downloaded_path *dl;

	if (dl_error)
		return -EINVAL;
	if (file_exists(uri_get_local(uri)) == 0)
		return 0;

	dl = pmalloc(sizeof(struct downloaded_path));
	dl->path = pstrdup(uri_get_local(uri));
	dl->visited = false;
	SLIST_INSERT_HEAD(&downloaded, dl, hook);
	return 0;
}

int
rsync_download(struct rpki_uri *uri)
{
	rsync_counter++;
	return pretend_download(uri);
}

int
http_download(struct rpki_uri *uri, curl_off_t ims, bool *changed)
{
	int error;
	https_counter++;
	error = pretend_download(uri);
	if (changed != NULL)
		*changed = error ? false : true;
	return error;
}

MOCK_ABORT_INT(rrdp_update, struct rpki_uri *uri)

/* Helpers */

static void
setup_test(void)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));

	dl_error = false;
	cache = cache_create(TAL_FILE);
	ck_assert_ptr_ne(NULL, cache);
	SLIST_INIT(&downloaded);
}

static void
run_cache_download(char const *url, int expected_error,
    unsigned int rsync_calls, unsigned int https_calls)
{
	struct rpki_uri *uri;
	enum uri_type type;

	if (str_starts_with(url, "https://"))
		type = UT_TA_HTTP;
	else if (str_starts_with(url, "rsync://"))
		type = UT_RPP;
	else
		ck_abort_msg("Bad protocol: %s", url);

	rsync_counter = 0;
	https_counter = 0;

	ck_assert_int_eq(0, uri_create(&uri, TAL_FILE, type, NULL, url));
	ck_assert_int_eq(expected_error, cache_download(cache, uri, 0, NULL));
	ck_assert_uint_eq(rsync_calls, rsync_counter);
	ck_assert_uint_eq(https_calls, https_counter);

	uri_refput(uri);
}

static struct cache_node *
node(char const *url, time_t attempt, int err, bool succeeded, time_t success,
    bool is_notif)
{
	enum uri_type type;
	struct cache_node *result;

	if (str_starts_with(url, "https://"))
		type = is_notif ? UT_NOTIF : UT_TA_HTTP;
	else if (str_starts_with(url, "rsync://"))
		type = UT_RPP;
	else
		ck_abort_msg("Bad protocol: %s", url);

	result = pzalloc(sizeof(struct cache_node));
	ck_assert_int_eq(0, uri_create(&result->url, TAL_FILE, type, NULL, url));
	result->attempt.ts = attempt;
	result->attempt.result = err;
	result->success.happened = succeeded;
	result->success.ts = success;

	return result;
}

#define NODE(url, err, succeeded, has_file) \
	node(url, has_file, err, succeeded, 0, 0)

static void
reset_visiteds(void)
{
	struct downloaded_path *path;
	SLIST_FOREACH(path, &downloaded, hook)
		path->visited = false;
}

static struct downloaded_path *
find_downloaded_path(struct cache_node *node)
{
	struct downloaded_path *path;

	SLIST_FOREACH(path, &downloaded, hook)
		if (strcmp(uri_get_local(node->url), path->path) == 0) {
			if (path->visited)
				return NULL;
			else {
				path->visited = true;
				return path;
			}
		}

	return NULL;
}

static void
fail_if_nonvisited(void)
{
	struct downloaded_path *path;
	SLIST_FOREACH(path, &downloaded, hook)
		if (!path->visited)
			ck_abort_msg("Unexpected cache file: %s", path->path);
}

static void
validate_node(struct cache_node *expected, struct cache_node *actual)
{
	if (expected == NULL) {
		ck_assert_ptr_eq(NULL, actual);
		return;
	}

	ck_assert_str_eq(uri_get_global(expected->url), uri_get_global(actual->url));
	/* ck_assert_int_eq(expected->attempt.ts, actual->attempt.ts); */
	ck_assert_int_eq(expected->attempt.result, actual->attempt.result);
	ck_assert_int_eq(expected->success.happened, actual->success.happened);
	/* ck_assert_int_eq(expected->success.ts, actual->success.ts); */
}

static void
validate_cache(int trash, ...)
{
	struct cache_node *expected = NULL;
	struct cache_node *e, *a, *tmp;
	struct downloaded_path *path;
	char const *key;
	va_list args;

	printf("------------------------------\n");
	printf("Expected nodes:\n");

	va_start(args, trash);
	while ((e = va_arg(args, struct cache_node *)) != NULL) {
		printf("- %s %s error:%u success:%u\n",
		    uri_get_global(e->url), uri_get_local(e->url),
		    e->attempt.result, e->success.happened);

		key = uri_get_global(e->url);
		HASH_ADD_KEYPTR(hh, expected, key, strlen(key), e);
	}
	va_end(args);
	printf("\n");

	printf("Actual nodes:\n");
	HASH_ITER(hh, cache->ht, a, tmp)
		printf("- %s %s attempt:%u success:%u\n",
		    uri_get_global(a->url), uri_get_local(a->url),
		    a->attempt.result, a->success.happened);
	printf("\n");

	printf("Files in cache:\n");
	SLIST_FOREACH(path, &downloaded, hook)
		printf("- %s\n", path->path);
	printf("\n");

	/* Compare expected and cache */
	reset_visiteds();

	HASH_ITER(hh, expected, e, tmp) {
		path = find_downloaded_path(e);
		if (e->attempt.ts) { /* "if should have cache file" */
			if (path == NULL)
				ck_abort_msg("Cached file is missing: %s",
				    uri_get_local(e->url));
			path->visited = true;
		} else {
			if (path != NULL) {
				ck_abort_msg("Cached file should not exist: %s",
				    path->path);
			}
		}
	}

	fail_if_nonvisited();

	/* Compare expected and actual */
	HASH_ITER(hh, cache->ht, a, tmp) {
		key = uri_get_global(a->url);
		HASH_FIND_STR(expected, key, e);
		if (e == NULL)
			ck_abort_msg("Unexpected actual: %s", key);

		validate_node(e, a);

		HASH_DEL(expected, e);
		uri_refput(e->url);
		free(e);
	}

	if (HASH_COUNT(expected) != 0)
		ck_abort_msg("Actual node is mising: %s",
		    uri_get_global(expected->url));
}

static void
new_iteration(bool outdate)
{
	struct cache_node *node, *tmp;
	time_t epoch;

	epoch = outdate ? get_days_ago(30) : get_days_ago(1);
	HASH_ITER(hh, cache->ht, node, tmp)
		node->attempt.ts = epoch;
}

static void
cache_reset(struct rpki_cache *cache)
{
	struct cache_node *node, *tmp;
	HASH_ITER(hh, cache->ht, node, tmp)
		delete_node(cache, node);
}

static void
cleanup_test(void)
{
	struct downloaded_path *path;

	dl_error = false;
	cache_destroy(cache);

	while (!SLIST_EMPTY(&downloaded)) {
		path = SLIST_FIRST(&downloaded);
		SLIST_REMOVE_HEAD(&downloaded, hook);
		free(path->path);
		free(path);
	}
}

/* Tests */

START_TEST(test_cache_download_rsync)
{
	setup_test();

	run_cache_download("rsync://a.b.c/d", 0, 1, 0);
	validate_cache(0, NODE("rsync://a.b.c/d/", 0, 1, true), NULL);

	/* Redownload same file, nothing should happen */
	run_cache_download("rsync://a.b.c/d", 0, 0, 0);
	validate_cache(0, NODE("rsync://a.b.c/d/", 0, 1, true), NULL);

	/*
	 * rsyncs are recursive, which means if we've been recently asked to
	 * download d, we needn't bother redownloading d/e.
	 */
	run_cache_download("rsync://a.b.c/d/e", 0, 0, 0);
	validate_cache(0, NODE("rsync://a.b.c/d/", 0, 1, true), NULL);

	/*
	 * rsyncs get truncated, because it results in much faster
	 * synchronization in practice.
	 * This is not defined in any RFCs; it's an effective standard,
	 * and there would be consequences for violating it.
	 */
	run_cache_download("rsync://x.y.z/m/n/o", 0, 1, 0);
	validate_cache(0,
	    NODE("rsync://a.b.c/d/", 0, 1, true),
	    NODE("rsync://x.y.z/m/", 0, 1, true),
	    NULL);

	/* Sibling */
	run_cache_download("rsync://a.b.c/e/f", 0, 1, 0);
	validate_cache(0,
	    NODE("rsync://a.b.c/d/", 0, 1, true),
	    NODE("rsync://a.b.c/e/", 0, 1, true),
	    NODE("rsync://x.y.z/m/", 0, 1, true),
	    NULL);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_download_rsync_error)
{
	setup_test();

	dl_error = false;
	run_cache_download("rsync://a.b.c/d", 0, 1, 0);
	dl_error = true;
	run_cache_download("rsync://a.b.c/e", -EINVAL, 1, 0);
	validate_cache(0,
	    NODE("rsync://a.b.c/d/", 0, 1, true),
	    NODE("rsync://a.b.c/e/", -EINVAL, 0, false),
	    NULL);

	/* Regardless of error, not reattempted because same iteration */
	dl_error = true;
	run_cache_download("rsync://a.b.c/e", -EINVAL, 0, 0);
	validate_cache(0,
	    NODE("rsync://a.b.c/d/", 0, 1, true),
	    NODE("rsync://a.b.c/e/", -EINVAL, 0, false),
	    NULL);

	dl_error = false;
	run_cache_download("rsync://a.b.c/e", -EINVAL, 0, 0);
	validate_cache(0,
	    NODE("rsync://a.b.c/d/", 0, 1, true),
	    NODE("rsync://a.b.c/e/", -EINVAL, 0, false),
	    NULL);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_cleanup_rsync)
{
	setup_test();

	/*
	 * First iteration: Tree is created. No prunes, because nothing's
	 * outdated.
	 */
	new_iteration(true);
	run_cache_download("rsync://a.b.c/d", 0, 1, 0);
	run_cache_download("rsync://a.b.c/e", 0, 1, 0);
	cache_cleanup(cache);
	validate_cache(0,
	    NODE("rsync://a.b.c/d/", 0, 1, true),
	    NODE("rsync://a.b.c/e/", 0, 1, true),
	    NULL);

	/* One iteration with no changes, for paranoia */
	new_iteration(true);
	run_cache_download("rsync://a.b.c/d", 0, 1, 0);
	run_cache_download("rsync://a.b.c/e", 0, 1, 0);
	cache_cleanup(cache);
	validate_cache(0,
		NODE("rsync://a.b.c/d/", 0, 1, true),
		NODE("rsync://a.b.c/e/", 0, 1, true),
		NULL);

	/* Add one sibling */
	new_iteration(true);
	run_cache_download("rsync://a.b.c/d", 0, 1, 0);
	run_cache_download("rsync://a.b.c/e", 0, 1, 0);
	run_cache_download("rsync://a.b.c/f", 0, 1, 0);
	cache_cleanup(cache);
	validate_cache(0,
		NODE("rsync://a.b.c/d/", 0, 1, true),
		NODE("rsync://a.b.c/e/", 0, 1, true),
		NODE("rsync://a.b.c/f/", 0, 1, true),
		NULL);

	/* Nodes don't get updated, but they're still too young. */
	new_iteration(false);
	cache_cleanup(cache);
	validate_cache(0,
		NODE("rsync://a.b.c/d/", 0, 1, true),
		NODE("rsync://a.b.c/e/", 0, 1, true),
		NODE("rsync://a.b.c/f/", 0, 1, true),
		NULL);

	/* Remove some branches */
	new_iteration(true);
	run_cache_download("rsync://a.b.c/d", 0, 1, 0);
	cache_cleanup(cache);
	validate_cache(0, NODE("rsync://a.b.c/d/", 0, 1, true), NULL);

	/* Remove old branch and add sibling at the same time */
	new_iteration(true);
	run_cache_download("rsync://a.b.c/e", 0, 1, 0);
	cache_cleanup(cache);
	validate_cache(0, NODE("rsync://a.b.c/e/", 0, 1, true), NULL);

	/* Try child */
	new_iteration(true);
	run_cache_download("rsync://a.b.c/e/f/g", 0, 1, 0);
	cache_cleanup(cache);
	validate_cache(0, NODE("rsync://a.b.c/e/", 0, 1, true), NULL);

	/* Parent again */
	new_iteration(true);
	run_cache_download("rsync://a.b.c/e", 0, 1, 0);
	cache_cleanup(cache);
	validate_cache(0, NODE("rsync://a.b.c/e/", 0, 1, true), NULL);

	/* Empty the tree */
	new_iteration(true);
	cache_cleanup(cache);
	validate_cache(0, NULL);

	/* Node exists, but file doesn't */
	new_iteration(true);
	run_cache_download("rsync://a.b.c/e", 0, 1, 0);
	run_cache_download("rsync://a.b.c/f", 0, 1, 0);
	validate_cache(0,
		NODE("rsync://a.b.c/e/", 0, 1, true),
		NODE("rsync://a.b.c/f/", 0, 1, true),
		NULL);
	ck_assert_int_eq(0, file_rm_rf("tmp/" TAL_FILE "/rsync/a.b.c/f"));
	cache_cleanup(cache);
	validate_cache(0, NODE("rsync://a.b.c/e/", 0, 1, true), NULL);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_cleanup_rsync_error)
{
	setup_test();

	/* Set up */
	dl_error = false;
	run_cache_download("rsync://a.b.c/d", 0, 1, 0);
	dl_error = true;
	run_cache_download("rsync://a.b.c/e", -EINVAL, 1, 0);
	validate_cache(0,
		NODE("rsync://a.b.c/d/", 0, 1, true),
		NODE("rsync://a.b.c/e/", -EINVAL, 0, false),
		NULL);

	/* Node gets deleted because cached file doesn't exist */
	cache_cleanup(cache);
	validate_cache(0, NODE("rsync://a.b.c/d/", 0, 1, true), NULL);

	/*
	 * Node and file do not get deleted, because the failure is still not
	 * that old.
	 * Deletion does not depend on success or failure.
	 */
	new_iteration(false);
	dl_error = true;
	run_cache_download("rsync://a.b.c/d", -EINVAL, 1, 0);
	validate_cache(0, NODE("rsync://a.b.c/d/", -EINVAL, 1, true), NULL);

	/* Error is old; gets deleted */
	new_iteration(true);
	cache_cleanup(cache);
	validate_cache(0, NULL);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_download_https)
{
	setup_test();

	/* Download *file* e. */
	run_cache_download("https://a.b.c/d/e", 0, 0, 1);
	validate_cache(0, NODE("https://a.b.c/d/e", 0, 1, 1), NULL);

	/* Download something else 1 */
	run_cache_download("https://a.b.c/e", 0, 0, 1);
	validate_cache(0,
	    NODE("https://a.b.c/d/e", 0, 1, 1),
	    NODE("https://a.b.c/e", 0, 1, 1),
	    NULL);

	/* Download something else 2 */
	run_cache_download("https://x.y.z/e", 0, 0, 1);
	validate_cache(0,
	    NODE("https://a.b.c/d/e", 0, 1, 1),
	    NODE("https://a.b.c/e", 0, 1, 1),
	    NODE("https://x.y.z/e", 0, 1, 1),
	    NULL);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_download_https_error)
{
	setup_test();

	dl_error = false;
	run_cache_download("https://a.b.c/d", 0, 0, 1);
	dl_error = true;
	run_cache_download("https://a.b.c/e", -EINVAL, 0, 1);
	validate_cache(0,
	    NODE("https://a.b.c/d", 0, 1, 1),
	    NODE("https://a.b.c/e", -EINVAL, 0, 0),
	    NULL);

	/* Regardless of error, not reattempted because same iteration */
	dl_error = true;
	run_cache_download("https://a.b.c/d", 0, 0, 0);
	dl_error = false;
	run_cache_download("https://a.b.c/e", -EINVAL, 0, 0);
	validate_cache(0,
	    NODE("https://a.b.c/d", 0, 1, 1),
	    NODE("https://a.b.c/e", -EINVAL, 0, 0),
	    NULL);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_cleanup_https)
{
	setup_test();

	/* First iteration; make a tree and clean it */
	new_iteration(true);
	run_cache_download("https://a.b.c/d", 0, 0, 1);
	run_cache_download("https://a.b.c/e", 0, 0, 1);
	cache_cleanup(cache);
	validate_cache(0,
		NODE("https://a.b.c/d", 0, 1, 1),
		NODE("https://a.b.c/e", 0, 1, 1),
		NULL);

	/* Remove one branch */
	new_iteration(true);
	run_cache_download("https://a.b.c/d", 0, 0, 1);
	cache_cleanup(cache);
	validate_cache(0, NODE("https://a.b.c/d", 0, 1, 1), NULL);

	/* Change the one branch */
	new_iteration(true);
	run_cache_download("https://a.b.c/e", 0, 0, 1);
	cache_cleanup(cache);
	validate_cache(0, NODE("https://a.b.c/e", 0, 1, 1), NULL);

	/* Add a child to the same branch, do not update the old one */
	new_iteration(true);
	run_cache_download("https://a.b.c/e/f/g", 0, 0, 1);
	cache_cleanup(cache);
	validate_cache(0,
		NODE("https://a.b.c/e/f/g", 0, 1, 1), NULL);

	/*
	 * Download parent, do not update child.
	 * Children need to die, because parent is now a file.
	 */
	new_iteration(true);
	run_cache_download("https://a.b.c/e/f", 0, 0, 1);
	cache_cleanup(cache);
	validate_cache(0, NODE("https://a.b.c/e/f", 0, 1, 1), NULL);

	/* Do it again. */
	new_iteration(true);
	run_cache_download("https://a.b.c/e", 0, 0, 1);
	cache_cleanup(cache);
	validate_cache(0, NODE("https://a.b.c/e", 0, 1, 1), NULL);

	/* Empty the tree */
	new_iteration(true);
	cache_cleanup(cache);
	validate_cache(0, NULL);

	/* Node exists, but file doesn't */
	new_iteration(true);
	run_cache_download("https://a.b.c/e", 0, 0, 1);
	run_cache_download("https://a.b.c/f/g/h", 0, 0, 1);
	validate_cache(0,
	    NODE("https://a.b.c/e", 0, 1, 1),
	    NODE("https://a.b.c/f/g/h", 0, 1, 1),
	    NULL);
	ck_assert_int_eq(0, file_rm_rf("tmp/" TAL_FILE "/https/a.b.c/f/g/h"));
	cache_cleanup(cache);
	validate_cache(0, NODE("https://a.b.c/e", 0, 1, 1), NULL);

	cleanup_test();
}
END_TEST

START_TEST(test_cache_cleanup_https_error)
{
	setup_test();

	/* Set up */
	dl_error = false;
	run_cache_download("https://a.b.c/d", 0, 0, 1);
	dl_error = true;
	run_cache_download("https://a.b.c/e", -EINVAL, 0, 1);
	validate_cache(0,
	    NODE("https://a.b.c/d", 0, 1, 1),
	    NODE("https://a.b.c/e", -EINVAL, 0, 0),
	    NULL);

	/* Deleted because file ENOENT. */
	cache_cleanup(cache);
	validate_cache(0,
	    NODE("https://a.b.c/d", 0, 1, 1),
	    NULL);

	/* Fail d */
	new_iteration(false);
	dl_error = true;
	run_cache_download("https://a.b.c/d", -EINVAL, 0, 1);
	validate_cache(0, NODE("https://a.b.c/d", -EINVAL, 1, 1), NULL);

	/* Not deleted, because not old */
	new_iteration(false);
	cache_cleanup(cache);
	validate_cache(0, NODE("https://a.b.c/d", -EINVAL, 1, 1), NULL);

	/* Become old */
	new_iteration(true);
	cache_cleanup(cache);
	validate_cache(0, NULL);

	cleanup_test();
}
END_TEST

START_TEST(test_dots)
{
	setup_test();

	run_cache_download("https://a.b.c/d", 0, 0, 1);
	validate_cache(0, NODE("https://a.b.c/d", 0, 1, 1), NULL);

	run_cache_download("https://a.b.c/d/.", 0, 0, 0);
	validate_cache(0, NODE("https://a.b.c/d", 0, 1, 1), NULL);

	run_cache_download("https://a.b.c/d/e/..", 0, 0, 0);
	validate_cache(0, NODE("https://a.b.c/d", 0, 1, 1), NULL);

	run_cache_download("https://a.b.c/./d/../e", 0, 0, 1);
	validate_cache(0,
	    NODE("https://a.b.c/d", 0, 1, 1),
	    NODE("https://a.b.c/./d/../e", 0, 1, 1),
	    NULL);

	cleanup_test();
}
END_TEST

START_TEST(test_tal_json)
{
	json_t *json;
	char *str;

	setup_test();

	ck_assert_int_eq(0, system("rm -rf tmp/"));
	ck_assert_int_eq(0, system("mkdir -p tmp/" TAL_FILE));

	add_node(cache, NODE("rsync://a.b.c/d", 0, 1, 0));
	add_node(cache, NODE("rsync://a.b.c/e", 1, 0, 0));
	add_node(cache, NODE("rsync://x.y.z/e", 0, 1, 0));
	add_node(cache, NODE("https://a/b", 1, 1, 0));
	add_node(cache, node("https://a/c", 0, 0, 1, 0, 1));

	json = build_tal_json(cache);
	ck_assert_int_eq(0, json_dump_file(json, "tmp/" TAL_FILE "/" TAL_METAFILE, JSON_COMPACT));

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

	validate_cache(0,
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
prepare_uri_list(struct uri_list *uris, ...)
{
	char const *str;
	enum uri_type type;
	struct rpki_uri *uri;
	va_list args;

	uris_init(uris);

	va_start(args, uris);
	while ((str = va_arg(args, char const *)) != NULL) {
		if (str_starts_with(str, "https://"))
			type = UT_TA_HTTP;
		else if (str_starts_with(str, "rsync://"))
			type = UT_RPP;
		else
			ck_abort_msg("Bad protocol: %s", str);
		ck_assert_int_eq(0, uri_create(&uri, TAL_FILE, type, NULL, str));
		uris_add(uris, uri);
	}
	va_end(args);
}

#define PREPARE_URI_LIST(uris, ...) prepare_uri_list(uris, ##__VA_ARGS__, NULL)

START_TEST(test_recover)
{
	struct uri_list uris;

	setup_test();

	/* Query on empty database */
	PREPARE_URI_LIST(&uris, "rsync://a.b.c/d", "https://a.b.c/d");
	ck_assert_ptr_eq(NULL, cache_recover(cache, &uris));
	uris_cleanup(&uris);

	/* Only first URI is cached */
	cache_reset(cache);
	run_cache_download("rsync://a/b/c", 0, 1, 0);

	PREPARE_URI_LIST(&uris, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(uris.array[0], cache_recover(cache, &uris));
	uris_cleanup(&uris);

	/* Only second URI is cached */
	cache_reset(cache);
	run_cache_download("https://d/e", 0, 0, 1);

	PREPARE_URI_LIST(&uris, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(uris.array[1], cache_recover(cache, &uris));
	uris_cleanup(&uris);

	/* Only third URI is cached */
	cache_reset(cache);
	run_cache_download("https://f", 0, 0, 1);

	PREPARE_URI_LIST(&uris, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(uris.array[2], cache_recover(cache, &uris));
	uris_cleanup(&uris);

	/* None was cached */
	cache_reset(cache);
	run_cache_download("rsync://d/e", 0, 1, 0);

	PREPARE_URI_LIST(&uris, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(NULL, cache_recover(cache, &uris));
	uris_cleanup(&uris);

	/*
	 * At present, cache_recover() can only be called after all of a
	 * download's URLs yielded failure.
	 * However, node.error can still be zero. This happens when the download
	 * was successful, but the RRDP code wasn't able to expand the snapshot
	 * or deltas.
	 */
	cache_reset(cache);

	add_node(cache, node("rsync://a/1", 100, 0, 1, 100, 0));
	add_node(cache, node("rsync://a/2", 100, 1, 1, 100, 0));
	add_node(cache, node("rsync://a/3", 200, 0, 1, 100, 0));
	add_node(cache, node("rsync://a/4", 200, 1, 1, 100, 0));
	add_node(cache, node("rsync://a/5", 100, 0, 1, 200, 0));
	add_node(cache, node("rsync://a/6", 100, 1, 1, 200, 0));
	add_node(cache, node("rsync://b/1", 100, 0, 0, 100, 0));
	add_node(cache, node("rsync://b/2", 100, 1, 0, 100, 0));
	add_node(cache, node("rsync://b/3", 200, 0, 0, 100, 0));
	add_node(cache, node("rsync://b/4", 200, 1, 0, 100, 0));
	add_node(cache, node("rsync://b/5", 100, 0, 0, 200, 0));
	add_node(cache, node("rsync://b/6", 100, 1, 0, 200, 0));

	/* Multiple successful caches: Prioritize the most recent one */
	PREPARE_URI_LIST(&uris, "rsync://a/1", "rsync://a/3", "rsync://a/5");
	ck_assert_ptr_eq(uris.array[2], cache_recover(cache, &uris));
	uris_cleanup(&uris);

	PREPARE_URI_LIST(&uris, "rsync://a/5", "rsync://a/1", "rsync://a/3");
	ck_assert_ptr_eq(uris.array[0], cache_recover(cache, &uris));
	uris_cleanup(&uris);

	/* No successful caches: No viable candidates */
	PREPARE_URI_LIST(&uris, "rsync://b/2", "rsync://b/4", "rsync://b/6");
	ck_assert_ptr_eq(NULL, cache_recover(cache, &uris));
	uris_cleanup(&uris);

	/* Status: CNF_SUCCESS is better than 0. */
	PREPARE_URI_LIST(&uris, "rsync://b/1", "rsync://a/1");
	ck_assert_ptr_eq(uris.array[1], cache_recover(cache, &uris));
	uris_cleanup(&uris);

	/*
	 * If CNF_SUCCESS && error, Fort will probably run into a problem
	 * reading the cached directory, because it's either outdated or
	 * recently corrupted.
	 * But it should still TRY to read it, as there's a chance the
	 * outdatedness is not that severe.
	 */
	PREPARE_URI_LIST(&uris, "rsync://a/2", "rsync://b/2");
	ck_assert_ptr_eq(uris.array[0], cache_recover(cache, &uris));
	uris_cleanup(&uris);

	/* Parents of downloaded nodes */
	PREPARE_URI_LIST(&uris, "rsync://a", "rsync://b");
	ck_assert_ptr_eq(NULL, cache_recover(cache, &uris));
	uris_cleanup(&uris);

	/* Try them all at the same time */
	PREPARE_URI_LIST(&uris,
	    "rsync://a", "rsync://a/1", "rsync://a/2", "rsync://a/3",
	    "rsync://a/4", "rsync://a/5", "rsync://a/6",
	    "rsync://b", "rsync://b/1", "rsync://b/2", "rsync://b/3",
	    "rsync://b/4", "rsync://b/5", "rsync://b/6",
	    "rsync://e/1");
	ck_assert_ptr_eq(uris.array[5], cache_recover(cache, &uris));
	uris_cleanup(&uris);

	cleanup_test();
}
END_TEST

/* Boilerplate */

static Suite *thread_pool_suite(void)
{
	Suite *suite;
	TCase *rsync , *https, *dot, *meta, *recover;

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
	tcase_add_test(meta, test_tal_json);

	recover = tcase_create("recover");
	tcase_add_test(recover, test_recover);

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
