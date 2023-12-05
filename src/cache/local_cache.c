#include "cache/local_cache.h"

#include <ftw.h>
#include <time.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "json_util.h"
#include "log.h"
#include "rrdp.h"
#include "data_structure/array_list.h"
#include "data_structure/path_builder.h"
#include "data_structure/uthash.h"
#include "http/http.h"
#include "rsync/rsync.h"

struct cache_node {
	struct rpki_uri *url;

	struct {
		time_t ts; /* Last download attempt's timestamp */
		int result; /* Last download attempt's result status code */
	} attempt;

	struct {
		/* Has a download attempt ever been successful? */
		bool happened;
		/* Last successful download timestamp. (Only if @happened.) */
		time_t ts;
	} success;

	UT_hash_handle hh; /* Hash table hook */
};

struct rpki_cache {
	char *tal;
	struct cache_node *ht;
	time_t startup_ts; /* When we started the last validation */
};

#define TAGNAME_URL "url"
#define TAGNAME_ATTEMPT_TS "attempt-timestamp"
#define TAGNAME_ATTEMPT_ERR "attempt-result"
#define TAGNAME_SUCCESS_TS "success-timestamp"
#define TAGNAME_IS_NOTIF "is-rrdp-notification"

static char *
get_json_filename(struct rpki_cache *cache)
{
	struct path_builder pb;
	return pb_init_cache(&pb, cache->tal, "metadata.json")
	    ? NULL : pb.string;
}

static struct cache_node *
json2node(struct rpki_cache *cache, json_t *json)
{
	struct cache_node *node;
	char const *url;
	bool is_notif;
	enum uri_type type;
	int error;

	node = pzalloc(sizeof(struct cache_node));

	error = json_get_str(json, TAGNAME_URL, &url);
	if (error) {
		if (error > 0)
			pr_op_err("Node is missing the '" TAGNAME_URL "' tag.");
		goto fail;
	}

	if (str_starts_with(url, "https://"))
		type = UT_HTTPS;
	else if (str_starts_with(url, "rsync://"))
		type = UT_RSYNC;
	else {
		pr_op_err("Unknown protocol: %s", url);
		goto fail;
	}

	error = json_get_bool(json, TAGNAME_IS_NOTIF, &is_notif);
	if (error < 0)
		goto fail;

	error = uri_create(&node->url, cache->tal, type, is_notif, NULL, url);
	if (error) {
		pr_op_err("Cannot parse '%s' into a URI.", url);
		goto fail;
	}

	error = json_get_ts(json, TAGNAME_ATTEMPT_TS, &node->attempt.ts);
	if (error) {
		if (error > 0)
			pr_op_err("Node '%s' is missing the '"
			    TAGNAME_ATTEMPT_TS "' tag.", url);
		goto fail;
	}

	if (json_get_int(json, TAGNAME_ATTEMPT_ERR, &node->attempt.result) < 0)
		goto fail;

	error = json_get_ts(json, TAGNAME_SUCCESS_TS, &node->success.ts);
	if (error < 0)
		goto fail;
	node->success.happened = (error == 0);

	pr_op_debug("Node '%s' loaded successfully.", url);
	return node;

fail:
	uri_refput(node->url);
	free(node);
	return NULL;
}

static struct cache_node*
find_node(struct rpki_cache *cache, struct rpki_uri *uri)
{
	char const *key = uri_get_local(uri);
	struct cache_node *result;
	HASH_FIND_STR(cache->ht, key, result);
	return result;
}

static void
add_node(struct rpki_cache *cache, struct cache_node *node)
{
	char const *key = uri_get_local(node->url);
	size_t keylen = strlen(key);
	HASH_ADD_KEYPTR(hh, cache->ht, key, keylen, node);
}

static void
load_metadata_json(struct rpki_cache *cache)
{
	char *filename;
	json_t *root;
	json_error_t jerror;
	size_t n;
	struct cache_node *node;

	/*
	 * Note: Loading metadata.json is one of few things Fort can fail at
	 * without killing itself. It's just a cache of a cache.
	 */

	filename = get_json_filename(cache);
	if (filename == NULL)
		return;

	root = json_load_file(filename, 0, &jerror);

	if (root == NULL) {
		if (json_error_code(&jerror) == json_error_cannot_open_file)
			pr_op_debug("%s does not exist.", filename);
		else
			pr_op_err("Json parsing failure at %s (%d:%d): %s",
			    filename, jerror.line, jerror.column, jerror.text);
		goto end;
	}
	if (json_typeof(root) != JSON_ARRAY) {
		pr_op_err("The root tag of %s is not an array.", filename);
		goto end;
	}

	for (n = 0; n < json_array_size(root); n++) {
		node = json2node(cache, json_array_get(root, n));
		if (node != NULL)
			add_node(cache, node);
	}

end:	json_decref(root);
	free(filename);
}

struct rpki_cache *
cache_create(char const *tal)
{
	struct rpki_cache *cache;
	cache = pzalloc(sizeof(struct rpki_cache));
	cache->tal = pstrdup(tal);
	cache->startup_ts = time(NULL);
	if (cache->startup_ts == (time_t) -1)
		pr_crit("time(NULL) returned (time_t) -1.");
	load_metadata_json(cache);
	return cache;
}

static json_t *
node2json(struct cache_node *node)
{
	json_t *json;

	json = json_object();
	if (json == NULL) {
		pr_op_err("json object allocation failure.");
		return NULL;
	}

	if (json_add_str(json, TAGNAME_URL, uri_get_global(node->url)))
		goto cancel;
	if (uri_is_notif(node->url))
		if (json_add_bool(json, TAGNAME_IS_NOTIF, true))
			goto cancel;
	if (json_add_date(json, TAGNAME_ATTEMPT_TS, node->attempt.ts))
		goto cancel;
	if (json_add_int(json, TAGNAME_ATTEMPT_ERR, node->attempt.result))
		goto cancel;
	if (node->success.happened)
		if (json_add_date(json, TAGNAME_SUCCESS_TS, node->success.ts))
			goto cancel;

	return json;

cancel:
	json_decref(json);
	return NULL;
}

static json_t *
build_metadata_json(struct rpki_cache *cache)
{
	struct cache_node *node, *tmp;
	json_t *root, *child;

	root = json_array();
	if (root == NULL)
		enomem_panic();

	HASH_ITER(hh, cache->ht, node, tmp) {
		child = node2json(node);
		if (child == NULL)
			continue;
		if (json_array_append_new(root, child)) {
			pr_op_err("Cannot push %s json node into json root; unknown cause.",
			    uri_op_get_printable(node->url));
			continue;
		}
	}

	return root;
}

static void
write_metadata_json(struct rpki_cache *cache)
{
	char *filename;
	struct json_t *json;

	json = build_metadata_json(cache);
	if (json == NULL)
		return;

	filename = get_json_filename(cache);
	if (filename == NULL)
		goto end;

	if (json_dump_file(json, filename, JSON_INDENT(2)))
		pr_op_err("Unable to write %s; unknown cause.", filename);

end:	json_decref(json);
	free(filename);
}

static int
get_url(struct rpki_uri *uri, const char *tal, struct rpki_uri **url)
{
	char const *guri, *c;
	char *guri2;
	unsigned int slashes;
	int error;

	if (uri_get_type(uri) != UT_RSYNC) {
		uri_refget(uri);
		*url = uri;
		return 0;
	}

	/*
	 * Careful with this code. rsync(1):
	 *
	 * > A trailing slash on the source changes this behavior to avoid
	 * > creating an additional directory level at the destination. You can
	 * > think of a trailing / on a source as meaning "copy the contents of
	 * > this directory" as opposed to "copy the directory by name", but in
	 * > both cases the attributes of the containing directory are
	 * > transferred to the containing directory on the destination. In
	 * > other words, each of the following commands copies the files in the
	 * > same way, including their setting of the attributes of /dest/foo:
	 * >
	 * >     rsync -av /src/foo  /dest
	 * >     rsync -av /src/foo/ /dest/foo
	 *
	 * This quirk does not behave consistently. In practice, if you rsync
	 * at the module level, rsync servers behave as if the trailing slash
	 * always existed.
	 *
	 * ie. the two following rsyncs behave identically:
	 *
	 * 	rsync -rtz rsync://repository.lacnic.net/rpki  potatoes
	 * 		(Copies the content of rpki to potatoes.)
	 * 	rsync -rtz rsync://repository.lacnic.net/rpki/ potatoes
	 * 		(Copies the content of rpki to potatoes.)
	 *
	 * Even though the following do not:
	 *
	 * 	rsync -rtz rsync://repository.lacnic.net/rpki/lacnic  potatoes
	 * 		(Copies lacnic to potatoes.)
	 * 	rsync -rtz rsync://repository.lacnic.net/rpki/lacnic/ potatoes
	 * 		(Copies the content of lacnic to potatoes.)
	 *
	 * This is important to us, because an inconsistent missing directory
	 * component will screw our URLs-to-cache mappings.
	 *
	 * My solution is to add the slash myself. That's all I can do to force
	 * it to behave consistently, it seems.
	 *
	 * But note: This only works if we're synchronizing a directory.
	 * But this is fine, because this hack stacks with the minimum common
	 * path performance hack.
	 */

	guri = uri_get_global(uri);
	slashes = 0;
	for (c = guri; *c != '\0'; c++) {
		if (*c == '/') {
			slashes++;
			if (slashes == 4)
				return __uri_create(url, tal, UT_RSYNC, false,
				    NULL, guri, c - guri + 1);
		}
	}

	if (slashes == 3 && *(c - 1) != '/') {
		guri2 = pstrdup(guri); /* Remove const */
		guri2[c - guri] = '/';
		error = __uri_create(url, tal, UT_RSYNC, false, NULL, guri2,
		    c - guri + 1);
		free(guri2);
		return error;
	}

	/*
	 * Minimum common path performance hack: rsync the rsync module root,
	 * not every RPP separately. The former is much faster.
	 */
	return pr_val_err("Can't rsync URL '%s': The URL seems to be missing a domain or rsync module.",
	    guri);
}

static bool
was_recently_downloaded(struct rpki_cache *cache, struct cache_node *node)
{
	return difftime(cache->startup_ts, node->attempt.ts) <= 0;
}

static int
cache_check(struct rpki_uri *url)
{
	int error;

	error = file_exists(uri_get_local(url));
	switch (error) {
	case 0:
		pr_val_debug("Offline mode, file is cached.");
		break;
	case ENOENT:
		pr_val_debug("Offline mode, file is not cached.");
		break;
	default:
		pr_val_debug("Offline mode, unknown result %d (%s)",
		    error, strerror(error));
	}

	return error;
}

/**
 * @changed only on HTTP.
 */
int
cache_download(struct rpki_cache *cache, struct rpki_uri *uri, bool *changed)
{
	struct rpki_uri *url;
	struct cache_node *node;
	int error;

	if (changed != NULL)
		*changed = false;

	error = get_url(uri, cache->tal, &url);
	if (error)
		return error;

	node = find_node(cache, url);
	if (node != NULL) {
		uri_refput(url);
		if (was_recently_downloaded(cache, node))
			return node->attempt.result;
		url = node->url;
	} else {
		node = pzalloc(sizeof(struct cache_node));
		node->url = url;
		add_node(cache, node);
	}

	switch (uri_get_type(url)) {
	case UT_RSYNC:
		error = config_get_rsync_enabled()
		    ? rsync_download(url)
		    : cache_check(url);
		break;
	case UT_HTTPS:
		error = config_get_http_enabled()
		    ? http_download(url, changed)
		    : cache_check(url);
		break;
	default:
		pr_crit("Unexpected URI type: %d", uri_get_type(url));
	}

	node->attempt.ts = time(NULL);
	if (node->attempt.ts == (time_t) -1)
		pr_crit("time(NULL) returned (time_t) -1");
	node->attempt.result = error;
	if (!error) {
		node->success.happened = true;
		node->success.ts = node->attempt.ts;
	}

	return error;
}

static int
download(struct rpki_cache *cache, struct rpki_uri *uri, bool use_rrdp,
    uris_dl_cb cb, void *arg)
{
	int error;

	pr_val_debug("Trying URL %s...", uri_get_global(uri));

	error = (use_rrdp && (uri_get_type(uri) == UT_HTTPS))
	    ? rrdp_update(uri)
	    : cache_download(cache, uri, NULL);
	if (error)
		return 1;

	return cb(uri, arg);
}

static int
download_uris(struct rpki_cache *cache, struct uri_list *uris,
    enum uri_type type, bool use_rrdp, uris_dl_cb cb, void *arg)
{
	struct rpki_uri **uri;
	int error;

	ARRAYLIST_FOREACH(uris, uri) {
		if (uri_get_type(*uri) == type) {
			error = download(cache, *uri, use_rrdp, cb, arg);
			if (error <= 0)
				return error;
		}
	}

	return 1;
}

/**
 * Assumes all the URIs are URLs, and represent different ways to access the
 * same content.
 *
 * Sequentially (in the order dictated by their priorities) attempts to update
 * (in the cache) the content pointed by each URL.
 * If a download succeeds, calls cb on it. If cb succeeds, returns without
 * trying more URLs.
 *
 * If none of the URLs download and callback properly, attempts to find one
 * that's already cached, and callbacks it.
 */
int
cache_download_alt(struct rpki_cache *cache, struct uri_list *uris,
    bool use_rrdp, uris_dl_cb cb, void *arg)
{
	struct rpki_uri **cursor, *uri;
	int error;

	if (config_get_http_priority() > config_get_rsync_priority()) {
		error = download_uris(cache, uris, UT_HTTPS, use_rrdp, cb, arg);
		if (error <= 0)
			return error;
		error = download_uris(cache, uris, UT_RSYNC, use_rrdp, cb, arg);
		if (error <= 0)
			return error;

	} else if (config_get_http_priority() < config_get_rsync_priority()) {
		error = download_uris(cache, uris, UT_RSYNC, use_rrdp, cb, arg);
		if (error <= 0)
			return error;
		error = download_uris(cache, uris, UT_HTTPS, use_rrdp, cb, arg);
		if (error <= 0)
			return error;

	} else {
		ARRAYLIST_FOREACH(uris, cursor) {
			error = download(cache, *cursor, use_rrdp, cb, arg);
			if (error <= 0)
				return error;
		}
	}

	uri = cache_recover(cache, uris, use_rrdp);
	return (uri != NULL) ? cb(uri, arg) : ESRCH;
}

/*
 * Highest to lowest priority:
 *
 * 1. Recent Success: !error, CNF_SUCCESS, high ts_success.
 * 2. Old Success: !error, CNF_SUCCESS, low ts_success.
 * 3. Previous Recent Success: error, CNF_SUCCESS, high ts_success.
 * 4. Previous Old Success: error, CNF_SUCCESS, old ts_success.
 * 5. No Success: !CNF_SUCCESS (completely unviable)
 */
static struct cache_node *
choose_better(struct cache_node *old, struct cache_node *new)
{
	if (!new->success.happened)
		return old;
	if (old == NULL)
		return new;

	/*
	 * We're gonna have to get subjective here.
	 * Should we prioritize a candidate that was successfully downloaded a
	 * long time ago (with no retries since), or one that failed recently?
	 * Both are terrible, but returning something is still better than
	 * returning nothing, because the validator might manage to salvage
	 * remnant cached ROAs that haven't expired yet.
	 */

	if (old->attempt.result && !new->attempt.result)
		return new;
	if (!old->attempt.result && new->attempt.result)
		return old;
	return (difftime(old->success.ts, new->success.ts) < 0) ? new : old;
}

struct uri_and_node {
	struct rpki_uri *uri;
	struct cache_node *node;
};

/* Separated because of unit tests. */
static void
__cache_recover(struct rpki_cache *cache, struct uri_list *uris, bool use_rrdp,
    struct uri_and_node *best)
{
	struct rpki_uri **uri;
	struct rpki_uri *url;
	struct uri_and_node cursor;

	ARRAYLIST_FOREACH(uris, uri) {
		cursor.uri = *uri;

		if (get_url(cursor.uri, cache->tal, &url) != 0)
			continue;
		cursor.node = find_node(cache, url);
		uri_refput(url);
		if (cursor.node == NULL)
			continue;

		if (choose_better(best->node, cursor.node) == cursor.node)
			*best = cursor;
	}
}

struct rpki_uri *
cache_recover(struct rpki_cache *cache, struct uri_list *uris, bool use_rrdp)
{
	struct uri_and_node best = { 0 };
	__cache_recover(cache, uris, use_rrdp, &best);
	return best.uri;
}

void
cache_print(struct rpki_cache *cache)
{
	struct cache_node *node, *tmp;

	HASH_ITER(hh, cache->ht, node, tmp)
		printf("- %s (%s): %ssuccess error:%d\n",
		    uri_get_local(node->url),
		    uri_get_global(node->url),
		    node->success.happened ? "" : "!",
		    node->attempt.result);
}

static bool
is_node_fresh(struct cache_node *node, time_t epoch)
{
	/* TODO This is a startup; probably complicate this. */
	return difftime(epoch, node->attempt.ts) < 0;
}

static void
delete_node(struct rpki_cache *cache, struct cache_node *node)
{
	HASH_DEL(cache->ht, node);
	uri_refput(node->url);
	free(node);
}

static void
delete_node_and_cage(struct rpki_cache *cache, struct cache_node *node)
{
	struct rpki_uri *cage;

	if (uri_is_notif(node->url)) {
		if (uri_create_cage(&cage, cache->tal, node->url) == 0) {
			pr_op_debug("Deleting cage %s.", uri_get_local(cage));
			file_rm_rf(uri_get_local(cage));
			uri_refput(cage);
		}
	}

	delete_node(cache, node);
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

static void
cleanup_node(struct rpki_cache *cache, struct cache_node *node,
    time_t last_week)
{
	char const *path;
	int error;

	path = uri_get_local(node->url);
	error = file_exists(path);
	switch (error) {
	case 0:
		break;
	case ENOENT:
		/* Node exists but file doesn't: Delete node */
		pr_op_debug("Node exists but file doesn't: %s", path);
		delete_node_and_cage(cache, node);
		return;
	default:
		pr_op_err("Trouble cleaning '%s'; stat() returned errno %d: %s",
		    uri_op_get_printable(node->url), error, strerror(error));
	}

	if (!is_node_fresh(node, last_week)) {
		pr_op_debug("Deleting expired cache element %s.", path);
		file_rm_rf(path);
		delete_node_and_cage(cache, node);
	}
}

/*
 * "Do not clean." List of URIs that should not be deleted from the cache.
 * Global because nftw doesn't have a generic argument.
 */
static struct uri_list dnc;
static pthread_mutex_t dnc_lock = PTHREAD_MUTEX_INITIALIZER;

static bool
is_cached(char const *_fpath)
{
	struct rpki_uri **node;
	char const *fpath, *npath;
	size_t c;

	/*
	 * This relies on paths being normalized, which is currently done by the
	 * URI constructors.
	 */

	ARRAYLIST_FOREACH(&dnc, node) {
		fpath = _fpath;
		npath = uri_get_local(*node);

		for (c = 0; fpath[c] == npath[c]; c++)
			if (fpath[c] == '\0')
				return true;
		if (fpath[c] == '\0' && npath[c] == '/')
			return true;
		if (npath[c] == '\0' && fpath[c] == '/')
			return true;
	}

	return false;
}

static int
delete_if_unknown(const char *fpath, const struct stat *sb, int typeflag,
    struct FTW *ftw)
{
	if (!is_cached(fpath)) {
		pr_op_debug("Deleting untracked file or directory %s.", fpath);
		remove(fpath);
	}
	return 0;
}

static void
delete_unknown_files(struct rpki_cache *cache)
{
	struct cache_node *node, *tmp;
	struct rpki_uri *cage;
	struct path_builder pb;
	int error;

	error = pb_init_cache(&pb, cache->tal, "metadata.json");
	if (error) {
		pr_op_err("Cannot delete unknown files from %s's cache: %s",
		    cache->tal, strerror(error));
		return;
	}

	mutex_lock(&dnc_lock);
	uris_init(&dnc);

	uris_add(&dnc, uri_create_cache(pb.string));
	HASH_ITER(hh, cache->ht, node, tmp) {
		uri_refget(node->url);
		uris_add(&dnc, node->url);

		if (!uri_is_notif(node->url))
			continue;

		if (uri_create_cage(&cage, cache->tal, node->url) != 0) {
			pr_op_err("Cannot generate %s's cage. I'm probably going to end up deleting it from the cache.",
			    uri_op_get_printable(node->url));
			continue;
		}
		uris_add(&dnc, cage);
	}

	pb_pop(&pb, true);
	/* TODO (performance) optimize that 32 */
	error = nftw(pb.string, delete_if_unknown, 32, FTW_PHYS);
	if (error)
		pr_op_warn("The cache cleanup ended prematurely with error code %d (%s)",
		    error, strerror(error));

	uris_cleanup(&dnc);
	mutex_unlock(&dnc_lock);

	pb_cleanup(&pb);
}

/*
 * Deletes unknown and old untraversed cached files, writes metadata into XML.
 */
static void
cache_cleanup(struct rpki_cache *cache)
{
	struct cache_node *node, *tmp;
	time_t last_week;

	pr_op_debug("Cleaning up old abandoned cache files.");
	last_week = get_days_ago(7);
	HASH_ITER(hh, cache->ht, node, tmp)
		cleanup_node(cache, node, last_week);

	pr_op_debug("Cleaning up unknown cache files.");
	delete_unknown_files(cache);
}

void
cache_destroy(struct rpki_cache *cache)
{
	struct cache_node *node, *tmp;

	cache_cleanup(cache);
	write_metadata_json(cache);

	HASH_ITER(hh, cache->ht, node, tmp)
		delete_node(cache, node);
	free(cache->tal);
	free(cache);
}
