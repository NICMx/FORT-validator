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

/* XXX force RRDP if one RPP fails to validate by rsync? */

struct cached_file {
	char *url;
	char *path;
	UT_hash_handle hh; /* Hash table hook */
};

struct cached_rpp {
	struct cached_file *ht;
};

#define CNF_RSYNC		(1 << 0)
/* Was it downloaded during the current cycle? */
#define CNF_DOWNLOADED		(1 << 1)
/* Was it read during the current cycle? */
#define CNF_TOUCHED		(1 << 2)
/*
 * Did it validate successfully (at least once) during the current cycle?
 * (It's technically possible for two different repositories to map to the same
 * cache node. One of them is likely going to fail validation.)
 */
#define CNF_VALIDATED		(1 << 3)
/* Withdrawn by RRDP? */
#define CNF_WITHDRAWN		(1 << 4)

struct cache_node {
	char const *name; /* Points to the last component of @url */
	char *url;
	int flags;
	/* Last successful download time, or zero */
	time_t mtim;
	/*
	 * If flags & CNF_DOWNLOADED, path to the temporal directory where we
	 * downloaded the latest refresh.
	 * (See --compare-dest at rsync(1). RRDP is basically the same.)
	 * Otherwise undefined.
	 */
	char *tmpdir;

	/* Tree parent. Only defined during cleanup. */
	struct cache_node *parent;
	/* Tree children. */
	struct cache_node *children;

	UT_hash_handle hh; /* Hash table hook */
};

static struct rpki_cache {
	struct cache_node root; /* It's a tree. */
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

/*
 * Returns perfect match. (Even if it needs to create it.)
 * Always consumes @path.
 *
 * Unit Test (perfect match):
 * 	root
 * 		a
 * 			b
 * 			c
 * - Find c
 * - Find a
 * - Find a/b
 * - Find a/b/c
 * - Find a/b/c/d
 */
static struct cache_node *
find_node(char *path, int flags)
{
	struct cache_node *node, *child;
	char *nm, *sp; /* name, saveptr */
	size_t keylen;

	node = &cache.root;
	nm = strtok_r(path + RPKI_SCHEMA_LEN, "/", &sp); // XXX

	for (; nm; nm = strtok_r(NULL, "/", &sp)) {
		keylen = strlen(nm);
		HASH_FIND(hh, node->children, nm, keylen, child);
		if (child == NULL)
			goto create_children;
		node = child;
		sp[-1] = '/'; /* XXX this will need a compliance unit test */
	}

	goto end;

create_children:
	for (; nm; nm = strtok_r(NULL, "/", &sp)) {
		child = pmalloc(sizeof(struct cache_node));
		child->url = pstrdup(path);
		child->name = strrchr(child->url, '/') + 1; // XXX
		child->flags = flags;

		keylen = strlen(nm);
		HASH_ADD_KEYPTR(hh, node->children, child->name, keylen, child);

		node = child;
		sp[-1] = '/';
	}

end:	free(path);
	return node;
}

/*
 * Returns perfect match or NULL. @msm will point to the Most Specific Match.
 * Always consumes @path.
 */
static struct cache_node *
find_msm(char *path, struct cache_node **msm)
{
	struct cache_node *node, *child;
	char *nm, *sp; /* name, saveptr */
	size_t keylen;

	*msm = NULL;
	node = &cache.root;
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

static char *
get_rsync_module(char const *url)
{
	char const *c;
	char *dup;
	unsigned int slashes;

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

	slashes = 0;
	for (c = url; *c != '\0'; c++) {
		if (*c == '/') {
			slashes++;
			if (slashes == 4)
				/* XXX test the if I rm'd here */
				return pstrndup(url, c - url + 1);
		}
	}

	if (slashes == 3 && c[-1] != '/') {
		dup = pmalloc(c - url + 2);
		memcpy(dup, url, c - url);
		dup[c - url] = '/';
		dup[c - url + 1] = '\0';
		return dup;
	}

	pr_val_err("Can't rsync URL '%s': The URL seems to be missing a domain or rsync module.",
	    url);
	return NULL;
}

static int
dl_rsync(struct cache_node *node)
{
	char *path;
	int error;

	if (!config_get_rsync_enabled()) {
		pr_val_debug("rsync is disabled.");
		return 1;
	}

	error = cache_tmpfile(&path);
	if (error)
		return error;

	/*
	 * XXX the slow (-p) version is unlikely to be necessary.
	 * Maybe this function should also short-circuit by parent.
	 */
	error = mkdir_p(path, true);
	if (error)
		goto cancel;

	// XXX looks like the third argument is redundant now.
	error = rsync_download(node->url, path, true);
	if (error)
		goto cancel;

	node->flags |= CNF_DOWNLOADED;
	node->mtim = time(NULL); // XXX catch -1
	node->tmpdir = path;
	return 0;

cancel:	free(path);
	return error;
}

static int
dl_http(struct cache_node *node)
{
	char *path;
	bool changed;
	int error;

	if (!config_get_http_enabled()) {
		pr_val_debug("HTTP is disabled.");
		return 1;
	}

	error = cache_tmpfile(&path);
	if (error)
		return error;

	error = http_download(node->url, path, node->mtim, &changed);
	if (error) {
		free(path);
		return error;
	}

	node->flags |= CNF_DOWNLOADED;
	if (changed)
		node->mtim = time(NULL); // XXX catch -1
	node->tmpdir = path;
	return 0;
}

static int
dl_rrdp(struct cache_node *node)
{
	char *path;
	int error;

	if (!config_get_http_enabled()) {
		pr_val_debug("HTTP is disabled.");
		return 1;
	}

	error = cache_tmpfile(&path);
	if (error)
		return error;

	// XXX needs to add all files to node.
	// Probably also update node itself.
	error = rrdp_update(path, node);
	if (error) {
		free(path);
		return error;
	}

	node->flags |= CNF_DOWNLOADED;
	node->mtim = time(NULL); // XXX catch -1
	node->tmpdir = path;
	return 0;
}

static int
download(struct cache_mapping *map, struct cache_node *node)
{
	switch (map_get_type(map)) {
	case MAP_RSYNC:
		return dl_rsync(node);
	case MAP_HTTP:
	case MAP_TMP:
		return dl_http(node);
	case MAP_NOTIF:
		return dl_rrdp(node);
	}

	pr_crit("Unreachable.");
	return -EINVAL; /* Warning shutupper */
}

/*
 * XXX review result sign
 */
static int
try_url(struct cache_mapping *map, bool online, maps_dl_cb cb, void *arg)
{
	bool is_rsync;
	char *url;
	struct cache_node *node;
	int error;

	// XXX if RRDP, @map needs to be unwrapped...

	is_rsync = map_get_type(map) == MAP_RSYNC;
	url = is_rsync
	    ? get_rsync_module(map_get_url(map))
	    : pstrdup(map_get_url(map));
	if (!url)
		return -EINVAL;

	pr_val_debug("Trying RPP URL %s...", url);

	/* XXX mutex */
	node = find_node(url, is_rsync ? CNF_RSYNC : 0);

	if (online && !(node->flags & CNF_DOWNLOADED)) {
		error = download(map, node);
		if (error) {
			pr_val_debug("RPP refresh failed.");
			return error;
		}
	}

	error = cb(node, arg);
	if (error) {
		pr_val_debug("RPP validation failed.");
		return error;
	}

	/* XXX commit the files (later, during cleanup) */
	pr_val_debug("RPP downloaded and validated successfully.");
	return 0;
}

static int
download_maps(struct map_list *maps, bool online, enum map_type type,
    maps_dl_cb cb, void *arg)
{
	struct cache_mapping **_map, *map;
	int error;

	ARRAYLIST_FOREACH(maps, _map) {
		map = *_map;

		if ((map_get_type(map) & type) != type)
			continue;

		error = try_url(map, online, cb, arg);
		if (error <= 0)
			return error;
	}

	return 1;
}

static int
try_alts(struct map_list *maps, bool online, maps_dl_cb cb, void *arg)
{
	struct cache_mapping **cursor;
	int error;

	/* XXX during cleanup, always preserve only one? */
	if (config_get_http_priority() > config_get_rsync_priority()) {
		error = download_maps(maps, online, MAP_HTTP, cb, arg);
		if (error <= 0)
			return error;
		return download_maps(maps, online, MAP_RSYNC, cb, arg);

	} else if (config_get_http_priority() < config_get_rsync_priority()) {
		error = download_maps(maps, online, MAP_RSYNC, cb, arg);
		if (error <= 0)
			return error;
		return download_maps(maps, online, MAP_HTTP, cb, arg);

	} else {
		ARRAYLIST_FOREACH(maps, cursor) {
			error = try_url(*cursor, online, cb, arg);
			if (error <= 0)
				return error;
		}
		return 1;
	}
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
cache_download_alt(struct map_list *maps, maps_dl_cb cb, void *arg)
{
	int error;

	error = try_alts(maps, true, cb, arg);
	if (error)
		error = try_alts(maps, false, cb, arg);

	return error;
}

static void
print_node(struct cache_node *node, unsigned int tabs)
{
	struct cache_node *child, *tmp;
	unsigned int i;

	for (i = 0; i < tabs; i++)
		printf("\t");

	printf("%s ", node->name);
	printf("%s", (node->flags & CNF_RSYNC) ? "RSYNC " : "");
	printf("%s", (node->flags & CNF_DOWNLOADED) ? "DL " : "");
	printf("%s", (node->flags & CNF_TOUCHED) ? "Touched " : "");
	printf("%s", (node->flags & CNF_VALIDATED) ? "Valid " : "");
	printf("%s\n", (node->flags & CNF_WITHDRAWN) ? "Withdrawn " : "");

	HASH_ITER(hh, node->children, child, tmp)
		print_node(child, tabs + 1);
}

/* Recursive; tests only. */
void
cache_print(struct rpki_cache *cache)
{
	print_node(&cache->root, 0);
}

#ifdef UNIT_TESTING
static void __delete_node_cb(struct cache_node const *);
#endif

static void
__delete_node(struct cache_node *node)
{
#ifdef UNIT_TESTING
	__delete_node_cb(node);
#endif

	if (node->parent != NULL)
		HASH_DEL(node->parent->children, node);
	free(node->url);
	free(node->tmpdir);
	free(node);
}

/*
 * Caveats:
 *
 * - node->parent has to be set.
 * - Don't use this on the root.
 */
static void
delete_node(struct cache_node *node)
{
	struct cache_node *parent;

	parent = node->parent;
	if (parent != NULL) {
		HASH_DEL(parent->children, node);
		node->parent = NULL;
	}

	do {
		while (node->children) {
			node->children->parent = node;
			node = node->children;
		}

		parent = node->parent;
		__delete_node(node);
		node = parent;
	} while (node != NULL);
}

/* Preorder. @cb returns whether the children should be traversed. */
static int
traverse_cache(bool (*cb)(struct cache_node *, char const *))
{
	struct cache_node *iter_start;
	struct cache_node *parent, *child;
	struct cache_node *tmp;
	struct path_builder pb;
	int error;

	pb_init(&pb);

	error = pb_append(&pb, cache.root.name);
	if (error)
		goto end;

	parent = &cache.root;
	iter_start = parent->children;
	if (iter_start == NULL)
		goto end;

reloop:	/* iter_start must not be NULL */
	HASH_ITER(hh, iter_start, child, tmp) {
		error = pb_append(&pb, child->name);
		if (error)
			goto end;

		child->parent = parent;
		if (cb(child, pb.string) && (child->children != NULL)) {
			parent = child;
			iter_start = parent->children;
			goto reloop;
		}

		pb_pop(&pb, true);
	}

	parent = iter_start->parent;
	do {
		if (parent == NULL)
			goto end;
		pb_pop(&pb, true);
		iter_start = parent->hh.next;
		parent = parent->parent;
	} while (iter_start == NULL);

	goto reloop;

end:	pb_cleanup(&pb);
	return error;
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

	if (node->flags & CNF_VALIDATED)
		/* XXX nftw() no longer needed; rename() is enough */
		file_merge_into(node->tmpdir, path);
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

static int
__remove_abandoned(const char *path, const struct stat *st, int typeflag,
    struct FTW *ftw)
{
	struct cache_node *pm; /* Perfect Match */
	struct cache_node *msm; /* Most Specific Match */
	struct timespec now;

	/* XXX node->parent has to be set */
	pm = find_msm(pstrdup(path), &msm);
	if (!pm && !(msm->flags & CNF_RSYNC))
		goto unknown; /* The traversal is depth-first */

	if (S_ISDIR(st->st_mode)) {
		/*
		 * rmdir() fails if the directory is not empty.
		 * This will happen most of the time.
		 */
		if (rmdir(path) == 0)
			delete_node(pm);
		else if (errno == ENOENT)
			delete_node(pm);

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
		delete_node(pm);
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
	char *root = join_paths(config_get_local_repository(), "rsync");
	nftw(root, __remove_abandoned, 32, FTW_DEPTH | FTW_PHYS); // XXX
	free(root);
}

/*
 * Deletes unknown and old untraversed cached files, writes metadata into XML.
 */
static void
cache_cleanup(struct rpki_cache *cache)
{
//	struct cache_node *node, *tmp;
//	time_t last_week;

	pr_op_debug("Committing successful RPPs.");
	traverse_cache(commit_rpp_delta);

//	pr_op_debug("Cleaning up temporal files.");
//	HASH_ITER(hh, cache->ht, node, tmp)
//		cleanup_tmp(cache, node);

	pr_op_debug("Cleaning up old abandoned and unknown cache files.");
	remove_abandoned();

	/* XXX delete nodes for which no file exists? */
}

//void
//cache_destroy(struct rpki_cache *cache)
//{
//	struct cache_node *node, *tmp;
//
//	cache_cleanup(cache);
//	write_tal_json(cache);
//
//	HASH_ITER(hh, cache->ht, node, tmp)
//		delete_node(cache, node);
//	free(cache);
//}
