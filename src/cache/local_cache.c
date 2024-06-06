#include "cache/local_cache.h"

#include <ftw.h>
#include <stdatomic.h>
#include <time.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "configure_ac.h"
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
	struct cache_mapping *map;

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

	struct cachefile_notification *notif;

	UT_hash_handle hh; /* Hash table hook */
};

struct rpki_cache {
	struct cache_node *ht;
	time_t startup_ts; /* When we started the last validation */
};

#define CACHE_METAFILE "cache.json"
#define TAGNAME_VERSION "fort-version"

#define CACHEDIR_TAG "CACHEDIR.TAG"
#define TMPDIR "tmp"

#define TAL_METAFILE "tal.json"
#define TAGNAME_TYPE "type"
#define TAGNAME_URL "url"
#define TAGNAME_ATTEMPT_TS "attempt-timestamp"
#define TAGNAME_ATTEMPT_ERR "attempt-result"
#define TAGNAME_SUCCESS_TS "success-timestamp"
#define TAGNAME_NOTIF "notification"

#define TYPEVALUE_TA_RSYNC "TA (rsync)"
#define TYPEVALUE_TA_HTTP "TA (HTTP)"
#define TYPEVALUE_RPP "RPP"
#define TYPEVALUE_NOTIF "RRDP Notification"

static atomic_uint file_counter;

static char *
get_cache_filename(char const *name, bool fatal)
{
	struct path_builder pb;
	int error;

	error = pb_init_cache(&pb, name);
	if (error) {
		if (fatal) {
			pr_crit("Cannot create path to %s: %s", name,
			    strerror(error));
		} else {
			pr_op_err("Cannot create path to %s: %s", name,
			    strerror(error));
			return NULL;
		}
	}

	return pb.string;
}

static int
write_simple_file(char const *filename, char const *content)
{
	FILE *file;
	int error;

	file = fopen(filename, "w");
	if (file == NULL)
		goto fail;

	if (fprintf(file, "%s", content) < 0)
		goto fail;

	fclose(file);
	return 0;

fail:
	error = errno;
	pr_op_err("Cannot write %s: %s", filename, strerror(error));
	if (file != NULL)
		fclose(file);
	return error;
}

static void
init_cache_metafile(void)
{
	char *filename;
	json_t *root;
	json_error_t jerror;
	char const *file_version;
	int error;

	filename = get_cache_filename(CACHE_METAFILE, true);
	root = json_load_file(filename, 0, &jerror);

	if (root == NULL) {
		if (json_error_code(&jerror) == json_error_cannot_open_file)
			pr_op_debug("%s does not exist.", filename);
		else
			pr_op_err("Json parsing failure at %s (%d:%d): %s",
			    filename, jerror.line, jerror.column, jerror.text);
		goto invalid_cache;
	}
	if (json_typeof(root) != JSON_OBJECT) {
		pr_op_err("The root tag of %s is not an object.", filename);
		goto invalid_cache;
	}

	error = json_get_str(root, TAGNAME_VERSION, &file_version);
	if (error) {
		if (error > 0)
			pr_op_err("%s is missing the " TAGNAME_VERSION " tag.",
			    filename);
		goto invalid_cache;
	}

	if (strcmp(file_version, PACKAGE_VERSION) == 0)
		goto end;

invalid_cache:
	pr_op_info("The cache appears to have been built by a different version of Fort. I'm going to clear it, just to be safe.");
	file_rm_rf(config_get_local_repository());

end:	json_decref(root);
	free(filename);
}

static void
init_cachedir_tag(void)
{
	char *filename;

	filename = get_cache_filename(CACHEDIR_TAG, false);
	if (filename == NULL)
		return;

	if (file_exists(filename) == ENOENT)
		write_simple_file(filename,
		   "Signature: 8a477f597d28d172789f06886806bc55\n"
		   "# This file is a cache directory tag created by Fort.\n"
		   "# For information about cache directory tags, see:\n"
		   "#	https://bford.info/cachedir/\n");

	free(filename);
}

static void
init_tmp_dir(void)
{
	char *dirname;
	int error;

	dirname = get_cache_filename(TMPDIR, true);

	error = mkdir_p(dirname, true);
	if (error)
		pr_crit("Cannot create %s: %s", dirname, strerror(error));

	free(dirname);
}

void
cache_setup(void)
{
	init_cache_metafile();
	init_tmp_dir();
	init_cachedir_tag();
}

void
cache_teardown(void)
{
	char *filename;

	filename = get_cache_filename(CACHE_METAFILE, false);
	if (filename == NULL)
		return;

	write_simple_file(filename, "{ \"" TAGNAME_VERSION "\": \""
	    PACKAGE_VERSION "\" }\n");
	free(filename);
}

/*
 * Returns a unique temporary file name in the local cache.
 *
 * The file will not be automatically deleted when it is closed or the program
 * terminates.
 *
 * The name of the function is inherited from tmpfile(3).
 *
 * The resulting string needs to be released.
 */
int
cache_tmpfile(char **filename)
{
	struct path_builder pb;
	int error;

	error = pb_init_cache(&pb, TMPDIR);
	if (error)
		return error;

	error = pb_append_u32(&pb, atomic_fetch_add(&file_counter, 1u));
	if (error) {
		pb_cleanup(&pb);
		return error;
	}

	*filename = pb.string;
	return 0;
}

static char *
get_tal_json_filename(void)
{
	struct path_builder pb;
	return pb_init_cache(&pb, TAL_METAFILE) ? NULL : pb.string;
}

static struct cache_node *
json2node(json_t *json)
{
	struct cache_node *node;
	char const *type_str;
	enum map_type type;
	char const *url;
	json_t *notif;
	int error;

	node = pzalloc(sizeof(struct cache_node));

	error = json_get_str(json, TAGNAME_TYPE, &type_str);
	if (error) {
		if (error > 0)
			pr_op_err("Node is missing the '" TAGNAME_TYPE "' tag.");
		goto fail;
	}

	if (strcmp(type_str, TYPEVALUE_TA_RSYNC) == 0)
		type = MAP_TA_RSYNC;
	else if (strcmp(type_str, TYPEVALUE_TA_HTTP) == 0)
		type = MAP_TA_HTTP;
	else if (strcmp(type_str, TYPEVALUE_RPP) == 0)
		type = MAP_RPP;
	else if (strcmp(type_str, TYPEVALUE_NOTIF) == 0)
		type = MAP_NOTIF;
	else {
		pr_op_err("Unknown node type: %s", type_str);
		goto fail;
	}

	error = json_get_str(json, TAGNAME_URL, &url);
	if (error) {
		if (error > 0)
			pr_op_err("Node is missing the '" TAGNAME_URL "' tag.");
		goto fail;
	}

	if (type == MAP_NOTIF) {
		error = json_get_object(json, TAGNAME_NOTIF, &notif);
		switch (error) {
		case 0:
			error = rrdp_json2notif(notif, &node->notif);
			if (error)
				goto fail;
			break;
		case ENOENT:
			node->notif = NULL;
			break;
		default:
			goto fail;
		}
	}

	error = map_create(&node->map, type, NULL, url);
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
	map_refput(node->map);
	rrdp_notif_free(node->notif);
	free(node);
	return NULL;
}

static struct cache_node *
find_node(struct rpki_cache *cache, struct cache_mapping *map)
{
	char const *key;
	struct cache_node *result;

	key = map_get_url(map);
	HASH_FIND_STR(cache->ht, key, result);

	return result;
}

static void
add_node(struct rpki_cache *cache, struct cache_node *node)
{
	char const *key = map_get_url(node->map);
	size_t keylen = strlen(key);
	HASH_ADD_KEYPTR(hh, cache->ht, key, keylen, node);
}

static void
load_tal_json(struct rpki_cache *cache)
{
	char *filename;
	json_t *root;
	json_error_t jerror;
	size_t n;
	struct cache_node *node;

	/*
	 * Note: Loading TAL_METAFILE is one of few things Fort can fail at
	 * without killing itself. It's just a cache of a cache.
	 */

	filename = get_tal_json_filename();
	if (filename == NULL)
		return;

	pr_op_debug("Loading %s.", filename);

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
		node = json2node(json_array_get(root, n));
		if (node != NULL)
			add_node(cache, node);
	}

end:	json_decref(root);
	free(filename);
}

struct rpki_cache *
cache_create(void)
{
	struct rpki_cache *cache;
	cache = pzalloc(sizeof(struct rpki_cache));
	cache->startup_ts = time(NULL);
	if (cache->startup_ts == (time_t) -1)
		pr_crit("time(NULL) returned (time_t) -1.");
	load_tal_json(cache);
	return cache;
}

static json_t *
node2json(struct cache_node *node)
{
	json_t *json;
	char const *type;
	json_t *notification;

	json = json_obj_new();
	if (json == NULL)
		return NULL;

	switch (map_get_type(node->map)) {
	case MAP_TA_RSYNC:
		type = TYPEVALUE_TA_RSYNC;
		break;
	case MAP_TA_HTTP:
		type = TYPEVALUE_TA_HTTP;
		break;
	case MAP_RPP:
		type = TYPEVALUE_RPP;
		break;
	case MAP_NOTIF:
		type = TYPEVALUE_NOTIF;
		break;
	default:
		goto cancel;
	}

	if (json_add_str(json, TAGNAME_TYPE, type))
		goto cancel;
	if (json_add_str(json, TAGNAME_URL, map_get_url(node->map)))
		goto cancel;
	if (node->notif != NULL) {
		notification = rrdp_notif2json(node->notif);
		if (json_object_add(json, TAGNAME_NOTIF, notification))
			goto cancel;
	}
	if (json_add_ts(json, TAGNAME_ATTEMPT_TS, node->attempt.ts))
		goto cancel;
	if (json_add_int(json, TAGNAME_ATTEMPT_ERR, node->attempt.result))
		goto cancel;
	if (node->success.happened)
		if (json_add_ts(json, TAGNAME_SUCCESS_TS, node->success.ts))
			goto cancel;

	return json;

cancel:
	json_decref(json);
	return NULL;
}

static json_t *
build_tal_json(struct rpki_cache *cache)
{
	struct cache_node *node, *tmp;
	json_t *root, *child;

	root = json_array_new();
	if (root == NULL)
		return NULL;

	HASH_ITER(hh, cache->ht, node, tmp) {
		child = node2json(node);
		if (child != NULL && json_array_append_new(root, child)) {
			pr_op_err("Cannot push %s json node into json root; unknown cause.",
			    map_op_get_printable(node->map));
			continue;
		}
	}

	return root;
}

static void
write_tal_json(struct rpki_cache *cache)
{
	char *filename;
	struct json_t *json;

	json = build_tal_json(cache);
	if (json == NULL)
		return;

	filename = get_tal_json_filename();
	if (filename == NULL)
		goto end;

	if (json_dump_file(json, filename, JSON_INDENT(2)))
		pr_op_err("Unable to write %s; unknown cause.", filename);

end:	json_decref(json);
	free(filename);
}

static int
fix_url(struct cache_mapping *map, struct cache_mapping **result)
{
	char const *url, *c;
	char *dup;
	unsigned int slashes;
	int error;

	if (map_get_type(map) != MAP_RPP)
		goto reuse_mapping;

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
	 *
	 * Minimum common path performance hack: rsync the rsync module root,
	 * not every RPP separately. The former is much faster.
	 */

	url = map_get_url(map);
	slashes = 0;
	for (c = url; *c != '\0'; c++) {
		if (*c == '/') {
			slashes++;
			if (slashes == 4) {
				if (c[1] == '\0')
					goto reuse_mapping;
				dup = pstrndup(url, c - url + 1);
				goto dup2url;
			}
		}
	}

	if (slashes == 3 && c[-1] != '/') {
		dup = pmalloc(c - url + 2);
		memcpy(dup, url, c - url);
		dup[c - url] = '/';
		dup[c - url + 1] = '\0';
		goto dup2url;
	}

	return pr_val_err("Can't rsync URL '%s': The URL seems to be missing a domain or rsync module.",
	    url);

reuse_mapping:
	map_refget(map);
	*result = map;
	return 0;

dup2url:
	error = map_create(result, MAP_RPP, NULL, dup);
	free(dup);
	return error;
}

static bool
was_recently_downloaded(struct rpki_cache *cache, struct cache_node *node)
{
	return difftime(cache->startup_ts, node->attempt.ts) <= 0;
}

static int
cache_check(struct cache_mapping *url)
{
	int error;

	error = file_exists(map_get_path(url));
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
 * @ims and @changed only on HTTP.
 * @ims can be zero, which means "no IMS."
 * @changed can be NULL.
 */
int
cache_download(struct rpki_cache *cache, struct cache_mapping *map,
    bool *changed, struct cachefile_notification ***notif)
{
	struct cache_mapping *map2;
	struct cache_node *node;
	int error;

	if (changed != NULL)
		*changed = false;

	error = fix_url(map, &map2);
	if (error)
		return error;

	node = find_node(cache, map2);
	if (node != NULL) {
		if (was_recently_downloaded(cache, node)) {
			error = node->attempt.result;
			goto end;
		}
	} else {
		node = pzalloc(sizeof(struct cache_node));
		node->map = map2;
		map_refget(map2);
		add_node(cache, node);
	}

	switch (map_get_type(map2)) {
	case MAP_TA_HTTP:
	case MAP_NOTIF:
	case MAP_TMP:
		error = config_get_http_enabled()
		   ? http_download(map2, node->success.ts, changed)
		   : cache_check(map2);
		break;
	case MAP_TA_RSYNC:
	case MAP_RPP:
		error = config_get_rsync_enabled()
		    ? rsync_download(map_get_url(map2), map_get_path(map2), true)
		    : cache_check(map2);
		break;
	default:
		pr_crit("Mapping type not downloadable: %d", map_get_type(map2));
	}

	node->attempt.ts = time(NULL);
	if (node->attempt.ts == (time_t) -1)
		pr_crit("time(NULL) returned (time_t) -1");
	node->attempt.result = error;
	if (!error) {
		node->success.happened = true;
		node->success.ts = node->attempt.ts;
	}

end:
	map_refput(map2);
	if (!error && (notif != NULL))
		*notif = &node->notif;
	return error;
}

static int
download(struct rpki_cache *cache, struct cache_mapping *map, maps_dl_cb cb,
    void *arg)
{
	int error;

	pr_val_debug("Trying URL %s...", map_get_url(map));

	switch (map_get_type(map)) {
	case MAP_TA_HTTP:
	case MAP_TA_RSYNC:
	case MAP_RPP:
		error = cache_download(cache, map, NULL, NULL);
		break;
	case MAP_NOTIF:
		error = rrdp_update(map);
		break;
	default:
		pr_crit("Mapping type is not a legal alt candidate: %u",
		    map_get_type(map));
	}

	return error ? 1 : cb(map, arg);
}

static int
download_maps(struct rpki_cache *cache, struct map_list *maps,
    enum map_type type, maps_dl_cb cb, void *arg)
{
	struct cache_mapping **map;
	int error;

	ARRAYLIST_FOREACH(maps, map) {
		if (map_get_type(*map) == type) {
			error = download(cache, *map, cb, arg);
			if (error <= 0)
				return error;
		}
	}

	return 1;
}

/**
 * Assumes the mappings represent different ways to access the same content.
 *
 * Sequentially (in the order dictated by their priorities) attempts to update
 * (in the cache) the content pointed by each mapping's URL.
 * If a download succeeds, calls cb on it. If cb succeeds, returns without
 * trying more URLs.
 *
 * If none of the URLs download and callback properly, attempts to find one
 * that's already cached, and callbacks it.
 */
int
cache_download_alt(struct rpki_cache *cache, struct map_list *maps,
    enum map_type http_type, enum map_type rsync_type, maps_dl_cb cb, void *arg)
{
	struct cache_mapping **cursor, *map;
	int error;

	if (config_get_http_priority() > config_get_rsync_priority()) {
		error = download_maps(cache, maps, http_type, cb, arg);
		if (error <= 0)
			return error;
		error = download_maps(cache, maps, rsync_type, cb, arg);
		if (error <= 0)
			return error;

	} else if (config_get_http_priority() < config_get_rsync_priority()) {
		error = download_maps(cache, maps, rsync_type, cb, arg);
		if (error <= 0)
			return error;
		error = download_maps(cache, maps, http_type, cb, arg);
		if (error <= 0)
			return error;

	} else {
		ARRAYLIST_FOREACH(maps, cursor) {
			error = download(cache, *cursor, cb, arg);
			if (error <= 0)
				return error;
		}
	}

	map = cache_recover(cache, maps);
	return (map != NULL) ? cb(map, arg) : ESRCH;
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

struct map_and_node {
	struct cache_mapping *map;
	struct cache_node *node;
};

/* Separated because of unit tests. */
static void
__cache_recover(struct rpki_cache *cache, struct map_list *maps,
    struct map_and_node *best)
{
	struct cache_mapping **map;
	struct cache_mapping *fixed;
	struct map_and_node cursor;

	ARRAYLIST_FOREACH(maps, map) {
		cursor.map = *map;

		if (fix_url(cursor.map, &fixed) != 0)
			continue;
		cursor.node = find_node(cache, fixed);
		map_refput(fixed);
		if (cursor.node == NULL)
			continue;

		if (choose_better(best->node, cursor.node) == cursor.node)
			*best = cursor;
	}
}

struct cache_mapping *
cache_recover(struct rpki_cache *cache, struct map_list *maps)
{
	struct map_and_node best = { 0 };
	__cache_recover(cache, maps, &best);
	return best.map;
}

void
cache_print(struct rpki_cache *cache)
{
	struct cache_node *node, *tmp;

	HASH_ITER(hh, cache->ht, node, tmp)
		printf("- %s (%s): %ssuccess error:%d\n",
		    map_get_path(node->map),
		    map_get_url(node->map),
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
	map_refput(node->map);
	rrdp_notif_free(node->notif);
	free(node);
}

static void
delete_node_and_cage(struct rpki_cache *cache, struct cache_node *node)
{
	struct cache_mapping *cage;

	if (map_get_type(node->map) == MAP_NOTIF) {
		if (map_create_cage(&cage, node->map) == 0) {
			pr_op_debug("Deleting cage %s.", map_get_path(cage));
			file_rm_rf(map_get_path(cage));
			map_refput(cage);
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
cleanup_tmp(struct rpki_cache *cache, struct cache_node *node)
{
	enum map_type type;
	char const *path;
	int error;

	type = map_get_type(node->map);
	if (type != MAP_NOTIF && type != MAP_TMP)
		return;

	path = map_get_path(node->map);
	pr_op_debug("Deleting temporal file '%s'.", path);
	error = file_rm_f(path);
	if (error)
		pr_op_err("Could not delete '%s': %s", path, strerror(error));

	if (type != MAP_NOTIF)
		delete_node(cache, node);
}

static void
cleanup_node(struct rpki_cache *cache, struct cache_node *node,
    time_t last_week)
{
	char const *path;
	int error;

	path = map_get_path(node->map);
	if (map_get_type(node->map) == MAP_NOTIF)
		goto skip_file;

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
		    map_op_get_printable(node->map), error, strerror(error));
	}

skip_file:
	if (!is_node_fresh(node, last_week)) {
		pr_op_debug("Deleting expired cache element %s.", path);
		file_rm_rf(path);
		delete_node_and_cage(cache, node);
	}
}

/*
 * "Do not clean." List of mappings that should not be deleted from the cache.
 * Global because nftw doesn't have a generic argument.
 */
static struct map_list dnc;
static pthread_mutex_t dnc_lock = PTHREAD_MUTEX_INITIALIZER;

static bool
is_cached(char const *_fpath)
{
	struct cache_mapping **node;
	char const *fpath, *npath;
	size_t c;

	/*
	 * This relies on paths being normalized, which is currently done by the
	 * struct cache_mapping constructors.
	 */

	ARRAYLIST_FOREACH(&dnc, node) {
		fpath = _fpath;
		npath = map_get_path(*node);

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
		errno = 0;
		if (remove(fpath) != 0)
			pr_op_err("Cannot delete '%s': %s", fpath, strerror(errno));
	}

	return 0;
}

/*
 * FIXME this needs to account I'm merging the TAL directories.
 * It might already work.
 */
static void
delete_unknown_files(struct rpki_cache *cache)
{
	struct cache_node *node, *tmp;
	struct cache_mapping *cage;
	struct path_builder pb;
	int error;

	error = pb_init_cache(&pb, TAL_METAFILE);
	if (error) {
		pr_op_err("Cannot delete unknown files from the cache: %s",
		    strerror(error));
		return;
	}

	mutex_lock(&dnc_lock);
	maps_init(&dnc);

	maps_add(&dnc, map_create_cache(pb.string));
	HASH_ITER(hh, cache->ht, node, tmp) {
		map_refget(node->map);
		maps_add(&dnc, node->map);

		if (map_get_type(node->map) != MAP_NOTIF)
			continue;

		if (map_create_cage(&cage, node->map) != 0) {
			pr_op_err("Cannot generate %s's cage. I'm probably going to end up deleting it from the cache.",
			    map_op_get_printable(node->map));
			continue;
		}
		maps_add(&dnc, cage);
	}

	pb_pop(&pb, true);
	/* TODO (performance) optimize that 32 */
	error = nftw(pb.string, delete_if_unknown, 32, FTW_PHYS);
	if (error)
		pr_op_warn("The cache cleanup ended prematurely with error code %d (%s)",
		    error, strerror(error));

	maps_cleanup(&dnc);
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

	pr_op_debug("Cleaning up temporal files.");
	HASH_ITER(hh, cache->ht, node, tmp)
		cleanup_tmp(cache, node);

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
	write_tal_json(cache);

	HASH_ITER(hh, cache->ht, node, tmp)
		delete_node(cache, node);
	free(cache);
}
