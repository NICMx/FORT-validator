/*
 * - We only need to keep nodes for the rsync root.
 * - The tree traverse only needs to touch files.
 * - RRDP needs caging.
 */

#include "cache.h"

#include <ftw.h>

#include "cachent.h"
#include "cachetmp.h"
#include "common.h"
#include "config.h"
#include "configure_ac.h"
#include "file.h"
#include "http.h"
#include "log.h"
#include "rpp.h"
#include "rsync.h"
#include "types/path.h"
#include "types/url.h"

/* XXX force RRDP if one RPP fails to validate by rsync? */

typedef int (*dl_cb)(struct cache_node *rpp);

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

#define CACHE_METAFILE "cache.json"
#define TAGNAME_VERSION "fort-version"

#define CACHEDIR_TAG "CACHEDIR.TAG"

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

static int
init_tmp_dir(void)
{
	char *dirname;
	int error;

	dirname = get_cache_filename(CACHE_TMPDIR, true);

	if (mkdir(dirname, CACHE_FILEMODE) < 0) {
		error = errno;
		if (error != EEXIST)
			return pr_op_err("Cannot create '%s': %s",
			    dirname, strerror(error));
	}

	free(dirname);
	return 0;
}

int
cache_setup(void)
{
	init_cache_metafile();
	init_tmp_dir();
	init_cachedir_tag();
	return 0;
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

//static char *
//get_tal_json_filename(void)
//{
//	struct path_builder pb;
//	return pb_init_cache(&pb, TAL_METAFILE) ? NULL : pb.string;
//}
//
//static struct cache_node *
//json2node(json_t *json)
//{
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
//	return NULL;
//}

static void
load_tal_json(void)
{
	cache.rsync = cachent_root_rsync();
	cache.https = cachent_root_https();

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

//static json_t *
//node2json(struct cache_node *node)
//{
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
//	return NULL;
//}
//
//static json_t *
//build_tal_json(struct rpki_cache *cache)
//{
//	struct cache_node *node, *tmp;
//	json_t *root, *child;
//
//	root = json_array_new();
//	if (root == NULL)
//		return NULL;
//
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
//}

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

static int
dl_rrdp(struct cache_node *rpp)
{
	int error;

	if (!config_get_http_enabled()) {
		pr_val_debug("HTTP is disabled.");
		return 1;
	}

	// XXX needs to add all files to node.
	// Probably also update node itself.
	// XXX maybe pr_crit() on !mft->parent?
	error = rrdp_update(rpp);
	if (error)
		pr_val_debug("RRDP RPP: Failed refresh.");

	return error;
}

static int
dl_rsync(struct cache_node *rpp)
{
	struct cache_node *module, *node;
	char *tmppath;
	int error;

	if (!config_get_rsync_enabled()) {
		pr_val_debug("rsync is disabled.");
		return 1;
	}

	module = get_rsync_module(rpp);
	if (module == NULL)
		return -EINVAL; // XXX

	error = cache_tmpfile(&tmppath);
	if (error)
		return error;

	error = rsync_download(module->url, tmppath,
	    (module->flags & CNF_CACHED) ? module->path : NULL);
	if (error) {
		free(tmppath);
		return error;
	}

	module->flags |= CNF_RSYNC | CNF_CACHED | CNF_FRESH | CNF_FREE_TMPPATH;
	module->mtim = time_nonfatal();
	module->tmppath = tmppath;

	for (node = rpp; node != module; node = node->parent) {
		node->flags |= RSYNC_INHERIT;
		node->mtim = module->mtim;
	}

	return 0;
}

static int
dl_http(struct cache_node *node)
{
	char *tmppath;
	time_t mtim;
	bool changed;
	int error;

	if (!config_get_http_enabled()) {
		pr_val_debug("HTTP is disabled.");
		return 1;
	}

	error = cache_tmpfile(&tmppath);
	if (error)
		return error;

	mtim = time_nonfatal();

	error = http_download(node->url, tmppath, node->mtim, &changed);
	if (error) {
		free(tmppath);
		return error;
	}

	node->flags |= CNF_CACHED | CNF_FRESH | CNF_FREE_TMPPATH;
	if (changed)
		node->mtim = mtim;
	node->tmppath = tmppath;
	return 0;
}

static char *
get_tmppath(struct cache_node *node)
{
	struct cache_node *ancestor;
	struct path_builder pb;
	size_t skiplen;

	if (node->tmppath != NULL)
		return node->tmppath;

	ancestor = node;
	do {
		ancestor = ancestor->parent;
		if (ancestor == NULL) {
			/* May warrant pr_crit(), but I'm chickening out. */
			pr_val_err("The download function did not set any tmppaths.");
			return NULL;
		}
	} while (ancestor->tmppath == NULL);

	skiplen = strlen(ancestor->path);
	if (strncmp(ancestor->path, node->path, skiplen) != 0)
		pr_crit("???"); // XXX

	pb_init(&pb);
	if (pb_append(&pb, ancestor->tmppath) != 0)
		goto cancel;
	if (pb_append(&pb, node->path + skiplen) != 0)
		goto cancel;

	node->flags |= CNF_FREE_TMPPATH;
	node->tmppath = pb.string;
	return pb.string;

cancel:	pb_cleanup(&pb);
	return NULL;
}

/* @uri is either a caRepository or a rpkiNotify */
static struct cache_node *
do_refresh(char const *uri, struct cache_node *root, dl_cb download)
{
	struct cache_node *node;

	if (!uri)
		return NULL; /* Protocol unavailable; ignore */

	pr_val_debug("Trying %s (online)...", uri);

	node = cachent_provide(root, uri);
	if (!node) {
		pr_val_err("Malformed URL: %s", uri);
		return NULL;
	}

	if (!(node->flags & CNF_FRESH)) {
		node->flags |= CNF_FRESH;
		node->dlerr = download(node);
	}
	if (node->dlerr)
		pr_val_debug("Refresh failed.");

	return node;
}

/* @url needs to outlive @map. */
int
cache_refresh_url(char *url, struct cache_mapping *map)
{
	struct cache_node *node = NULL;

	// XXX mutex
	// XXX review result signs

	if (url_is_https(url))
		node = do_refresh(url, cache.https, dl_http);
	else if (url_is_rsync(url))
		node = do_refresh(url, cache.rsync, dl_rsync);
	if (!node)
		return EINVAL;

	// XXX might want to const url and path.
	// Alternatively, strdup path so the caller can't corrupt our string.
	map->url = url;
	map->path = get_tmppath(node);
	return (map->path != NULL) ? 0 : EINVAL;
}

/* @url needs to outlive @map. */
int
cache_fallback_url(char *url, struct cache_mapping *map)
{
	struct cache_node *node = NULL;

	if (url_is_https(url))
		node = cachent_provide(cache.https, url);
	else if (url_is_rsync(url))
		node = cachent_provide(cache.rsync, url);
	if (!node)
		return EINVAL;

	map->url = url;
	map->path = node->path;
	return 0;
}

/*
 * Attempts to refresh the RPP described by @sias, returns the resulting
 * repository's mapping.
 */
int
cache_refresh_sias(struct sia_uris *sias, struct cache_mapping *map)
{
	struct cache_node *hnode;
	struct cache_node *rnode;

	// XXX Make sure somewhere validates rpkiManifest matches caRepository.
	// XXX mutex
	// XXX review result signs
	// XXX normalize rpkiNotify & caRepository?

	hnode = do_refresh(sias->rpkiNotify, cache.https, dl_rrdp);
	if (hnode && !hnode->dlerr) {
		map->url = hnode->url;
		map->path = hnode->tmppath;
		return 0;
	}

	rnode = do_refresh(sias->caRepository, cache.rsync, dl_rsync);
	if (rnode && !rnode->dlerr) {
		map->url = rnode->url;
		map->path = rnode->tmppath;
		return 0;
	}

	if (hnode && cachent_is_cached(hnode)) {
		map->url = hnode->url;
		map->path = hnode->path;
		return 0;
	}

	if (hnode && cachent_is_cached(rnode)) {
		map->url = hnode->url;
		map->path = hnode->path;
		return 0;
	}

	return EINVAL;
}

void
cache_print(void)
{
	cachent_print(cache.rsync);
	cachent_print(cache.https);
}

static void
prune_rsync(void)
{
	struct cache_node *domain, *tmp1;
	struct cache_node *module, *tmp2;
	struct cache_node *child, *tmp3;

	HASH_ITER(hh, cache.rsync->children, domain, tmp1)
		HASH_ITER(hh, domain->children, module, tmp2)
			HASH_ITER(hh, module->children, child, tmp3) {
				pr_op_debug("Removing leftover: %s", child->url);
				module->flags |= cachent_delete(child);
			}
}

static bool
commit_rpp_delta(struct cache_node *node)
{
	struct cache_node *child, *tmp;
	int error;

	pr_op_debug("Commiting %s", node->url);

	if (node == cache.rsync || node == cache.https) {
		pr_op_debug("Root; nothing to commit.");
		goto branch;
	}

	if (node->tmppath == NULL) {
		if (node->children) {
			pr_op_debug("Branch.");
			goto branch;
		} else {
			pr_op_debug("Unchanged leaf; nothing to commit.");
			return true;
		}
	}

	if (node->flags & CNF_VALID) {
		pr_op_debug("Validation successful; committing.");
		error = file_merge_into(node->tmppath, node->path);
		if (error)
			printf("rename errno: %d\n", error); // XXX
		/* XXX Think more about the implications of this. */
		HASH_ITER(hh, node->children, child, tmp)
			cachent_delete(child);
	} else {
		pr_op_debug("Validation unsuccessful; rollbacking.");
		/* XXX just do remove()? */
		file_rm_f(node->tmppath);
	}

	free(node->tmppath);
	node->tmppath = NULL;
	return true;

branch:	/* Clean up state flags */
	node->flags &= ~(CNF_CACHED | CNF_FRESH | CNF_TOUCHED | CNF_VALID);
	if (node->tmppath) {
		free(node->tmppath);
		node->tmppath = NULL;
	}
	return true;
}

static int
rmf(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	if (remove(fpath) < 0)
		pr_op_warn("Can't remove %s: %s", fpath, strerror(errno));
	else
		pr_op_debug("Removed %s.", fpath);
	return 0;
}

static void
cleanup_tmp(void)
{
	char *tmpdir = get_cache_filename(CACHE_TMPDIR, true);
	if (nftw(tmpdir, rmf, 32, FTW_DEPTH | FTW_PHYS))
		pr_op_warn("Cannot empty the cache's tmp directory: %s",
		    strerror(errno));
	free(tmpdir);
}

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
	char const *lookup;
	struct cache_node *pm; /* Perfect Match */
	struct cache_node *msm; /* Most Specific Match */
	struct timespec now;

	// XXX
	lookup = path + strlen(config_get_local_repository());
	while (lookup[0] == '/')
		lookup++;
	pr_op_debug("Removing if abandoned: %s", lookup);

	pm = cachent_find(nftw_root, lookup, &msm);
	if (pm == cache.rsync || pm == cache.https) {
		pr_op_debug("Root; skipping.");
		return 0;
	}
	if (!msm) {
		pr_op_debug("Not matched by the tree; unknown.");
		goto unknown;
	}
	if (!pm && !(msm->flags & CNF_RSYNC)) {
		/* XXX what about HTTP? */
		pr_op_debug("RRDP and no perfect match; unknown.");
		goto unknown; /* The traversal is depth-first */
	}

	if (S_ISDIR(st->st_mode)) {
		/*
		 * rmdir() fails if the directory is not empty.
		 * This will happen most of the time.
		 */
		if (rmdir(path) == 0) {
			pr_op_debug("Directory empty; purging node.");
			cachent_delete(pm);
		} else if (errno == ENOENT) {
			pr_op_debug("Directory does not exist; purging node.");
			cachent_delete(pm);
		} else {
			pr_op_debug("Directory exists and has contents; preserving.");
		}

	} else if (S_ISREG(st->st_mode)) {

//		if ((msm->flags & CNF_RSYNC) || !pm || (pm->flags & CNF_WITHDRAWN))
		clock_gettime(CLOCK_REALTIME, &now); // XXX
		PR_DEBUG_MSG("%ld > %ld", now.tv_sec - st->st_atim.tv_sec, cfg_cache_threshold());
		if (now.tv_sec - st->st_atim.tv_sec > cfg_cache_threshold()) {
			pr_op_debug("Too old; abandoned.");
			goto abandoned;
		}
		pr_op_debug("Still young; preserving.");

	} else {
		pr_op_debug("Unknown type; abandoned.");
		goto abandoned;
	}

	return 0;

abandoned:
	if (pm)
		cachent_delete(pm);
unknown:
	if (remove(path) < 0)
		PR_DEBUG_MSG("remove(): %s", strerror(errno)); // XXX
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

static bool
remove_orphaned(struct cache_node *node)
{
	if (file_exists(node->path) == ENOENT) {
		pr_op_debug("Missing file; deleting node: %s", node->path);
		cachent_delete(node);

		if (node == cache.https)
			cache.https = NULL;
		else if (node == cache.rsync)
			cache.rsync = NULL;

		return false;
	}

	return true;
}

/*
 * Deletes unknown and old untraversed cached files, writes metadata into XML.
 */
static void
cleanup_cache(void)
{
	pr_op_debug("Ditching redundant rsync nodes.");
	prune_rsync();

	pr_op_debug("Committing successful RPPs.");
	cachent_traverse(cache.rsync, commit_rpp_delta);
	cachent_traverse(cache.https, commit_rpp_delta);

	pr_op_debug("Cleaning up temporal files.");
	cleanup_tmp();

	pr_op_debug("Cleaning up old abandoned and unknown cache files.");
	remove_abandoned();

	pr_op_debug("Cleaning up orphaned nodes.");
	cachent_traverse(cache.rsync, remove_orphaned);
	cachent_traverse(cache.https, remove_orphaned);
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
