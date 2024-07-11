/*
 * Current design notes:
 *
 * - We only need to keep nodes for the rsync root.
 * - The tree traverse only needs to touch files.
 */

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
#include "types/str.h"
#include "types/url.h"

/* XXX force RRDP if one RPP fails to validate by rsync? */

struct cached_file {
	char *url;
	char *path;
	UT_hash_handle hh; /* Hash table hook */
};

struct cached_rpp {
	struct cached_file *ht;
};

static struct rpki_cache {
	struct cache_node *rsync;
	struct cache_node *https;
//	time_t startup_ts; /* When we started the last validation */
} cache;

static atomic_uint file_counter;

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

#define TYPEVALUE_TA_HTTP "TA (HTTP)"
#define TYPEVALUE_RPP "RPP"
#define TYPEVALUE_NOTIF "RRDP Notification"

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
//	char *filename;
//	json_t *root;
//	json_error_t jerror;
//	char const *file_version;
//	int error;
//
//	filename = get_cache_filename(CACHE_METAFILE, true);
//	root = json_load_file(filename, 0, &jerror);
//
//	if (root == NULL) {
//		if (json_error_code(&jerror) == json_error_cannot_open_file)
//			pr_op_debug("%s does not exist.", filename);
//		else
//			pr_op_err("Json parsing failure at %s (%d:%d): %s",
//			    filename, jerror.line, jerror.column, jerror.text);
//		goto invalid_cache;
//	}
//	if (json_typeof(root) != JSON_OBJECT) {
//		pr_op_err("The root tag of %s is not an object.", filename);
//		goto invalid_cache;
//	}
//
//	error = json_get_str(root, TAGNAME_VERSION, &file_version);
//	if (error) {
//		if (error > 0)
//			pr_op_err("%s is missing the " TAGNAME_VERSION " tag.",
//			    filename);
//		goto invalid_cache;
//	}
//
//	if (strcmp(file_version, PACKAGE_VERSION) == 0)
//		goto end;
//
//invalid_cache:
//	pr_op_info("The cache appears to have been built by a different version of Fort. I'm going to clear it, just to be safe.");
//	file_rm_rf(config_get_local_repository());
//
//end:	json_decref(root);
//	free(filename);
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

	error = mkdir(dirname, true);
	if (error != EEXIST)
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
 * Returns a unique temporary file name in the local cache. Note, it's a name,
 * and it's pretty much reserved. The file itself will not be created.
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
//	struct cache_node *node;
//	char const *type_str;
//	enum map_type type;
//	char const *url;
//	json_t *notif;
//	int error;
//
//	node = pzalloc(sizeof(struct cache_node));
//
//	error = json_get_str(json, TAGNAME_TYPE, &type_str);
//	if (error) {
//		if (error > 0)
//			pr_op_err("Node is missing the '" TAGNAME_TYPE "' tag.");
//		goto fail;
//	}
//
//	if (strcmp(type_str, TYPEVALUE_TA_HTTP) == 0)
//		type = MAP_HTTP;
//	else if (strcmp(type_str, TYPEVALUE_RPP) == 0)
//		type = MAP_RSYNC;
//	else if (strcmp(type_str, TYPEVALUE_NOTIF) == 0)
//		type = MAP_NOTIF;
//	else {
//		pr_op_err("Unknown node type: %s", type_str);
//		goto fail;
//	}
//
//	error = json_get_str(json, TAGNAME_URL, &url);
//	if (error) {
//		if (error > 0)
//			pr_op_err("Node is missing the '" TAGNAME_URL "' tag.");
//		goto fail;
//	}
//
//	if (type == MAP_NOTIF) {
//		error = json_get_object(json, TAGNAME_NOTIF, &notif);
//		switch (error) {
//		case 0:
//			error = rrdp_json2notif(notif, &node->notif);
//			if (error)
//				goto fail;
//			break;
//		case ENOENT:
//			node->notif = NULL;
//			break;
//		default:
//			goto fail;
//		}
//	}
//
//	error = map_create(&node->map, type, url);
//	if (error) {
//		pr_op_err("Cannot parse '%s' into a URI.", url);
//		goto fail;
//	}
//
//	error = json_get_ts(json, TAGNAME_ATTEMPT_TS, &node->attempt.ts);
//	if (error) {
//		if (error > 0)
//			pr_op_err("Node '%s' is missing the '"
//			    TAGNAME_ATTEMPT_TS "' tag.", url);
//		goto fail;
//	}
//
//	if (json_get_int(json, TAGNAME_ATTEMPT_ERR, &node->attempt.result) < 0)
//		goto fail;
//
//	error = json_get_ts(json, TAGNAME_SUCCESS_TS, &node->success.ts);
//	if (error < 0)
//		goto fail;
//	node->success.happened = (error == 0);
//
//	pr_op_debug("Node '%s' loaded successfully.", url);
//	return node;
//
//fail:
//	map_refput(node->map);
//	rrdp_notif_free(node->notif);
//	free(node);
	return NULL;
}

static void
load_tal_json(void)
{
	cache.rsync = cachent_create_root("rsync:");
	cache.https = cachent_create_root("https:");

//	char *filename;
//	json_t *root;
//	json_error_t jerror;
//	size_t n;
//	struct cache_node *node;
//
//	/*
//	 * Note: Loading TAL_METAFILE is one of few things Fort can fail at
//	 * without killing itself. It's just a cache of a cache.
//	 */
//
//	filename = get_tal_json_filename();
//	if (filename == NULL)
//		return;
//
//	pr_op_debug("Loading %s.", filename);
//
//	root = json_load_file(filename, 0, &jerror);
//
//	if (root == NULL) {
//		if (json_error_code(&jerror) == json_error_cannot_open_file)
//			pr_op_debug("%s does not exist.", filename);
//		else
//			pr_op_err("Json parsing failure at %s (%d:%d): %s",
//			    filename, jerror.line, jerror.column, jerror.text);
//		goto end;
//	}
//	if (json_typeof(root) != JSON_ARRAY) {
//		pr_op_err("The root tag of %s is not an array.", filename);
//		goto end;
//	}
//
//	for (n = 0; n < json_array_size(root); n++) {
//		node = json2node(json_array_get(root, n));
//		if (node != NULL)
//			add_node(cache, node);
//	}
//
//end:	json_decref(root);
//	free(filename);
}

void
cache_prepare(void)
{
	memset(&cache, 0, sizeof(cache));
	load_tal_json();
}

static json_t *
node2json(struct cache_node *node)
{
//	json_t *json;
//	char const *type;
//	json_t *notification;
//
//	json = json_obj_new();
//	if (json == NULL)
//		return NULL;
//
//	switch (map_get_type(node->map)) {
//	case MAP_HTTP:
//		type = TYPEVALUE_TA_HTTP;
//		break;
//	case MAP_RSYNC:
//		type = TYPEVALUE_RPP;
//		break;
//	case MAP_NOTIF:
//		type = TYPEVALUE_NOTIF;
//		break;
//	default:
//		goto cancel;
//	}
//
//	if (json_add_str(json, TAGNAME_TYPE, type))
//		goto cancel;
//	if (json_add_str(json, TAGNAME_URL, map_get_url(node->map)))
//		goto cancel;
//	if (node->notif != NULL) {
//		notification = rrdp_notif2json(node->notif);
//		if (json_object_add(json, TAGNAME_NOTIF, notification))
//			goto cancel;
//	}
//	if (json_add_ts(json, TAGNAME_ATTEMPT_TS, node->attempt.ts))
//		goto cancel;
//	if (json_add_int(json, TAGNAME_ATTEMPT_ERR, node->attempt.result))
//		goto cancel;
//	if (node->success.happened)
//		if (json_add_ts(json, TAGNAME_SUCCESS_TS, node->success.ts))
//			goto cancel;
//
//	return json;
//
//cancel:
//	json_decref(json);
	return NULL;
}

static json_t *
build_tal_json(struct rpki_cache *cache)
{
//	struct cache_node *node, *tmp;
//	json_t *root, *child;
//
//	root = json_array_new();
//	if (root == NULL)
		return NULL;

//	HASH_ITER(hh, cache->ht, node, tmp) {
//		child = node2json(node);
//		if (child != NULL && json_array_append_new(root, child)) {
//			pr_op_err("Cannot push %s json node into json root; unknown cause.",
//			    map_op_get_printable(node->map));
//			continue;
//		}
//	}
//
//	return root;
}

static void
write_tal_json(void)
{
//	char *filename;
//	struct json_t *json;
//
//	json = build_tal_json(cache);
//	if (json == NULL)
//		return;
//
//	filename = get_tal_json_filename();
//	if (filename == NULL)
//		goto end;
//
//	if (json_dump_file(json, filename, JSON_INDENT(2)))
//		pr_op_err("Unable to write %s; unknown cause.", filename);
//
//end:	json_decref(json);
//	free(filename);
}

/*
 * Returns perfect match or NULL. @msm will point to the Most Specific Match.
 * Always consumes @path.
 */
static struct cache_node *
find_msm(struct cache_node *root, char *path, struct cache_node **msm)
{
	struct cache_node *node, *child;
	char *nm, *sp; /* name, saveptr */
	size_t keylen;

	*msm = NULL;
	node = root;
	nm = strtok_r(path + RPKI_SCHEMA_LEN, "/", &sp); // XXX

	for (; nm; nm = strtok_r(NULL, "/", &sp)) {
		keylen = strlen(nm);
		HASH_FIND(hh, node->children, nm, keylen, child);
		if (child == NULL) {
			free(path);
			*msm = node;
			return NULL;
		}
		node = child;
	}

	free(path);
	*msm = node;
	return node;
}

/*
 * The "rsync module" is the component immediately after the domain.
 *
 * get_rsync_module(rsync://a.b.c/d/e/f/potato.mft) = d
 */
static struct cache_node *
get_rsync_module(struct cache_node *node)
{
	struct cache_node *gp; /* Grandparent */

	if (!node || !node->parent || !node->parent->parent)
		return NULL;

	for (gp = node->parent->parent; gp->parent != NULL; gp = gp->parent)
		node = node->parent;
	return node;
}

static struct cache_node *
get_rsync_rpp(char const *caRepository, struct cache_node *rpkiManifest)
{
	struct cache_node *node;
	char *normal;

	normal = url_normalize(caRepository);
	if (normal == NULL)
		return NULL;

	for (node = rpkiManifest; node != NULL; node = node->parent)
		if (strcmp(node->url, normal) == 0) {
			free(normal);
			return node;
		}

	free(normal);
	return NULL;
}

static int
dl_rsync(char const *caRepository, struct cache_node *mft)
{
	struct cache_node *module, *node;
	char *path;
	int error;

	if (!config_get_rsync_enabled()) {
		pr_val_debug("rsync is disabled.");
		return 1;
	}

	module = get_rsync_module(mft);
	if (module == NULL) {
		return -EINVAL; // XXX
	}
	mft->rpp = get_rsync_rpp(caRepository, mft);
	if (!mft->rpp)
		return pr_val_err("Manifest '%s' does not seem to be inside its publication point '%s'.",
		    mft->url, caRepository);

	error = cache_tmpfile(&path);
	if (error)
		return error;

	// XXX looks like the third argument is redundant now.
	error = rsync_download(module->url, path, true);
	if (error) {
		free(path);
		return error;
	}

	module->flags |= CNF_RSYNC | CNF_CACHED | CNF_FRESH;
	module->mtim = time(NULL); // XXX catch -1
	module->tmpdir = path;

	for (node = mft; node != module; node = node->parent) {
		node->flags |= RSYNC_INHERIT;
		node->mtim = module->mtim;
		if (mft) {
			node->rpp = mft->rpp;
			if (node == mft->rpp)
				mft = NULL;
		}
	}

	return 0;
}

static int
dl_http(struct cache_node *node)
{
	if (!config_get_http_enabled()) {
		pr_val_debug("HTTP is disabled.");
		return 1;
	}

	return http_download_cache_node(node);
}

static int
dl_rrdp(char const *notif_url, struct cache_node *mft)
{
	if (!config_get_http_enabled()) {
		pr_val_debug("HTTP is disabled.");
		return 1;
	}

	// XXX needs to add all files to node. Probably also update node itself.
	// XXX maybe pr_crit() on !mft->parent?
	return rrdp_update(cachent_provide(cache.https, notif_url), mft->parent);

//	node->flags |= CNF_FRESH;
//	node->mtim = time(NULL); // XXX catch -1
//	node->tmpdir = path;
}

static int
download(char const *uri, enum map_type type, struct cache_node *mft)
{
	switch (type) {
	case MAP_RSYNC:
		return dl_rsync(uri, mft);
	case MAP_HTTP:
		return dl_http(mft);
	case MAP_NOTIF:
		return dl_rrdp(uri, mft);
	}

	pr_crit("Unreachable.");
	return -EINVAL; /* Warning shutupper */
}

/*
 * XXX review result sign
 *
 * uri is a rpkiNotify or a caRepository.
 */
static int
try_uri(struct cache_node *mft, char const *uri, enum map_type type,
    bool online, maps_dl_cb cb, void *arg)
{
	int error;

	pr_val_debug("Trying %s...", uri);

	if (online) {
		error = download(uri, type, mft);
		if (error) {
			pr_val_debug("RPP refresh failed.");
			return error;
		}
	}

	error = cb(mft->rpp, arg);
	if (error) {
		pr_val_debug("RPP validation failed.");
		return error;
	}

	/* XXX commit the files (later, during cleanup) */
	pr_val_debug("RPP downloaded and validated successfully.");
	return 0;
}

/**
 * Assumes the URIs represent different ways to access the same content.
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
cache_download_alt(struct sia_uris *uris, maps_dl_cb cb, void *arg)
{
	struct cache_node *mft;
	int online;
	int error = 0;

	/* XXX mutex */
	/* XXX if parent is downloaded, child is downloaded. */
	mft = cachent_provide(cache.rsync, uris->rpkiManifest);

	if (mft->flags & CNF_FRESH)
		return cb(mft->rpp, arg); // XXX can rpp be NULL?

	for (online = 1; online >= 0; online--) {
		if (uris->rpkiNotify) {
			error = try_uri(mft, uris->rpkiNotify, MAP_NOTIF,
			    online, cb, arg);
			if (error <= 0)
				return error;
		}
		error = try_uri(mft, uris->caRepository, MAP_RSYNC,
		    online, cb, arg);
		if (error <= 0)
			return error;
	}

	return error;
}

void
cache_print(void)
{
	cachent_print(cache.rsync);
	cachent_print(cache.https);
}

/*
 * XXX this needs to be hit only by files now
 * XXX result is redundant
 */
static bool
commit_rpp_delta(struct cache_node *node, char const *path)
{
	if (node->tmpdir == NULL)
		return true; /* Not updated */

	if (node->flags & CNF_VALID)
		rename(node->tmpdir, path); // XXX
	else
		/* XXX same; just do remove(). */
		/* XXX and rename "tmpdir" into "tmp". */
		file_rm_f(node->tmpdir);

	free(node->tmpdir);
	node->tmpdir = NULL;
	return true;
}

//static bool
//is_node_fresh(struct cache_node *node, time_t epoch)
//{
//	/* TODO This is a startup; probably complicate this. */
//	return difftime(epoch, node->attempt.ts) < 0;
//}
//
//static void
//delete_node(struct rpki_cache *cache, struct cache_node *node)
//{
//	HASH_DEL(cache->ht, node);
//	map_refput(node->map);
//	rrdp_notif_free(node->notif);
//	free(node);
//}
//
//static void
//delete_node_and_cage(struct rpki_cache *cache, struct cache_node *node)
//{
//	struct cache_mapping *cage;
//
//	if (map_get_type(node->map) == MAP_NOTIF) {
//		if (map_create_cage(&cage, node->map) == 0) {
//			pr_op_debug("Deleting cage %s.", map_get_path(cage));
//			file_rm_rf(map_get_path(cage));
//			map_refput(cage);
//		}
//	}
//
//	delete_node(cache, node);
//}
//
//static time_t
//get_days_ago(int days)
//{
//	time_t tt_now, last_week;
//	struct tm tm;
//	int error;
//
//	tt_now = time(NULL);
//	if (tt_now == (time_t) -1)
//		pr_crit("time(NULL) returned (time_t) -1.");
//	if (localtime_r(&tt_now, &tm) == NULL) {
//		error = errno;
//		pr_crit("localtime_r(tt, &tm) returned error: %s",
//		    strerror(error));
//	}
//	tm.tm_mday -= days;
//	last_week = mktime(&tm);
//	if (last_week == (time_t) -1)
//		pr_crit("mktime(tm) returned (time_t) -1.");
//
//	return last_week;
//}
//
//static void
//cleanup_tmp(struct rpki_cache *cache, struct cache_node *node)
//{
//	enum map_type type;
//	char const *path;
//	int error;
//
//	type = map_get_type(node->map);
//	if (type != MAP_NOTIF && type != MAP_TMP)
//		return;
//
//	path = map_get_path(node->map);
//	pr_op_debug("Deleting temporal file '%s'.", path);
//	error = file_rm_f(path);
//	if (error)
//		pr_op_err("Could not delete '%s': %s", path, strerror(error));
//
//	if (type != MAP_NOTIF)
//		delete_node(cache, node);
//}
//
//static void
//cleanup_node(struct rpki_cache *cache, struct cache_node *node,
//    time_t last_week)
//{
//	char const *path;
//	int error;
//
//	path = map_get_path(node->map);
//	if (map_get_type(node->map) == MAP_NOTIF)
//		goto skip_file;
//
//	error = file_exists(path);
//	switch (error) {
//	case 0:
//		break;
//	case ENOENT:
//		/* Node exists but file doesn't: Delete node */
//		pr_op_debug("Node exists but file doesn't: %s", path);
//		delete_node_and_cage(cache, node);
//		return;
//	default:
//		pr_op_err("Trouble cleaning '%s'; stat() returned errno %d: %s",
//		    map_op_get_printable(node->map), error, strerror(error));
//	}
//
//skip_file:
//	if (!is_node_fresh(node, last_week)) {
//		pr_op_debug("Deleting expired cache element %s.", path);
//		file_rm_rf(path);
//		delete_node_and_cage(cache, node);
//	}
//}
//
///*
// * "Do not clean." List of mappings that should not be deleted from the cache.
// * Global because nftw doesn't have a generic argument.
// */
//static struct map_list dnc;
//static pthread_mutex_t dnc_lock = PTHREAD_MUTEX_INITIALIZER;
//
//static bool
//is_cached(char const *_fpath)
//{
//	struct cache_mapping **node;
//	char const *fpath, *npath;
//	size_t c;
//
//	/*
//	 * This relies on paths being normalized, which is currently done by the
//	 * struct cache_mapping constructors.
//	 */
//
//	ARRAYLIST_FOREACH(&dnc, node) {
//		fpath = _fpath;
//		npath = map_get_path(*node);
//
//		for (c = 0; fpath[c] == npath[c]; c++)
//			if (fpath[c] == '\0')
//				return true;
//		if (fpath[c] == '\0' && npath[c] == '/')
//			return true;
//		if (npath[c] == '\0' && fpath[c] == '/')
//			return true;
//	}
//
//	return false;
//}

static struct cache_node *nftw_root;

static int
nftw_remove_abandoned(const char *path, const struct stat *st,
    int typeflag, struct FTW *ftw)
{
	struct cache_node *pm; /* Perfect Match */
	struct cache_node *msm; /* Most Specific Match */
	struct timespec now;

	/* XXX node->parent has to be set */
	pm = find_msm(nftw_root, pstrdup(path), &msm);
	if (!pm && !(msm->flags & CNF_RSYNC))
		goto unknown; /* The traversal is depth-first */

	if (S_ISDIR(st->st_mode)) {
		/*
		 * rmdir() fails if the directory is not empty.
		 * This will happen most of the time.
		 */
		if (rmdir(path) == 0)
			cachent_delete(pm);
		else if (errno == ENOENT)
			cachent_delete(pm);

	} else if (S_ISREG(st->st_mode)) {
		if (pm->flags & (CNF_RSYNC | CNF_WITHDRAWN)) {
			clock_gettime(CLOCK_REALTIME, &now); // XXX
			if (now.tv_sec - st->st_atim.tv_sec > cfg_cache_threshold())
				goto abandoned;
		}

	} else {
		goto abandoned;
	}

	return 0;

abandoned:
	if (pm)
		cachent_delete(pm);
unknown:
	remove(path); // XXX
	return 0;
}

/*
 * Note: It'll probably be healthy if touched nodes also touch their parents.
 * You don't always need to go up all the way to the root.
 * But I'm afraid this will hit the mutexes.
 */
static void
remove_abandoned(void)
{
	char *rootpath;

	rootpath = join_paths(config_get_local_repository(), "rsync");

	nftw_root = cache.rsync;
	nftw(rootpath, nftw_remove_abandoned, 32, FTW_DEPTH | FTW_PHYS); // XXX

	strcpy(rootpath + strlen(rootpath) - 5, "https");

	nftw_root = cache.https;
	nftw(rootpath, nftw_remove_abandoned, 32, FTW_DEPTH | FTW_PHYS); // XXX

	free(rootpath);
}

/*
 * Deletes unknown and old untraversed cached files, writes metadata into XML.
 */
static void
cleanup_cache(void)
{
//	struct cache_node *node, *tmp;
//	time_t last_week;

	pr_op_debug("Committing successful RPPs.");
	cachent_traverse(cache.rsync, commit_rpp_delta);
	cachent_traverse(cache.https, commit_rpp_delta);

//	pr_op_debug("Cleaning up temporal files.");
//	HASH_ITER(hh, cache->ht, node, tmp)
//		cleanup_tmp(cache, node);

	pr_op_debug("Cleaning up old abandoned and unknown cache files.");
	remove_abandoned();

	/* XXX delete nodes for which no file exists? */
}

void
cache_commit(void)
{
	cleanup_cache();
	write_tal_json();
	cachent_delete(cache.rsync);
	cachent_delete(cache.https);
}

void
sias_init(struct sia_uris *sias)
{
	memset(sias, 0, sizeof(*sias));
}

void
sias_cleanup(struct sia_uris *sias)
{
	free(sias->caRepository);
	free(sias->rpkiNotify);
	free(sias->rpkiManifest);
}
