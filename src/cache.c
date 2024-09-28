#include "cache.h"

#include <ftw.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "alloc.h"
#include "cachetmp.h"
#include "common.h"
#include "config.h"
#include "configure_ac.h"
#include "file.h"
#include "http.h"
#include "log.h"
#include "rpp.h"
#include "rrdp.h"
#include "rsync.h"
#include "types/path.h"
#include "types/url.h"
#include "types/uthash.h"

struct cache_node {
	struct cache_mapping map;

	int fresh;		/* Refresh already attempted? */
	int dlerr;		/* Result code of recent download attempt */
	time_t mtim;		/* Last successful download time, or zero */

	struct rrdp_state *rrdp;

	UT_hash_handle hh;	/* Hash table hook */
};

typedef int (*dl_cb)(struct cache_node *rpp);

struct cache_table {
	char const *name;
	bool enabled;
	unsigned int next_id;
	size_t pathlen;
	struct cache_node *nodes; /* Hash Table */
	dl_cb download;
};

static struct rpki_cache {
	/* Latest view of the remote rsync modules */
	struct cache_table rsync;
	/* Latest view of the remote HTTPS TAs */
	struct cache_table https;
	/* Latest view of the remote RRDP cages */
	struct cache_table rrdp;
	/* Committed RPPs and TAs (offline fallback hard links) */
	struct cache_table fallback;
} cache;

struct cache_cage {
	struct cache_node *refresh;
	struct cache_node *fallback;
};

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

#ifdef UNIT_TESTING
static void __delete_node_cb(struct cache_node const *);
#endif

static void
delete_node(struct cache_table *tbl, struct cache_node *node)
{
#ifdef UNIT_TESTING
	__delete_node_cb(node);
#endif

	HASH_DEL(tbl->nodes, node);

	free(node->map.url);
	free(node->map.path);
	if (node->rrdp)
		rrdp_state_cleanup(node->rrdp);
	free(node);
}

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

static int dl_rsync(struct cache_node *);
static int dl_http(struct cache_node *);
static int dl_rrdp(struct cache_node *);

static void
init_table(struct cache_table *tbl, char const *name, bool enabled, dl_cb dl)
{
	memset(tbl, 0, sizeof(*tbl));
	tbl->name = name;
	tbl->enabled = enabled;
	tbl->pathlen = strlen(config_get_local_repository()) + strlen(name) + 6;
	tbl->download = dl;
}

static void
init_tables(void)
{
	init_table(&cache.rsync, "rsync", config_get_rsync_enabled(), dl_rsync);
	init_table(&cache.rsync, "https", config_get_http_enabled(), dl_http);
	init_table(&cache.rsync, "rrdp", config_get_http_enabled(), dl_rrdp);
	init_table(&cache.fallback, "fallback", true, NULL);
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
	init_tables();
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

static int
dl_rsync(struct cache_node *module)
{
	int error;

	error = rsync_download(&module->map);
	if (error)
		return error;

	module->mtim = time_nonfatal(); /* XXX probably not needed */
	return 0;
}

static int
dl_rrdp(struct cache_node *notif)
{
	time_t mtim;
	bool changed;
	int error;

	mtim = time_nonfatal();

	error = rrdp_update(&notif->map, notif->mtim, &changed, &notif->rrdp);
	if (error)
		return error;

	if (changed)
		notif->mtim = mtim;
	return 0;
}

static int
dl_http(struct cache_node *file)
{
	time_t mtim;
	bool changed;
	int error;

	mtim = time_nonfatal();

	error = http_download(file->map.url, file->map.path,
	    file->mtim, &changed);
	if (error)
		return error;

	if (changed)
		file->mtim = mtim;
	return 0;
}

static struct cache_node *
find_node(struct cache_table *tbl, char const *url, size_t urlen)
{
	struct cache_node *node;
	HASH_FIND(hh, tbl->nodes, url, urlen, node);
	return node;
}

static char *
create_path(struct cache_table *tbl)
{
	char *path;
	int len;

	do {
		path = pmalloc(tbl->pathlen);

		len = snprintf(path, tbl->pathlen, "%s/%s/%X",
		    config_get_local_repository(), tbl->name, tbl->next_id);
		if (len < 0) {
			pr_val_err("Cannot compute new cache path: Unknown cause.");
			return NULL;
		}
		if (len < tbl->pathlen) {
			tbl->next_id++;
			return path; /* Happy path */
		}

		tbl->pathlen++;
		free(path);
	} while (true);
}

static struct cache_node *
provide_node(struct cache_table *tbl, char const *url)
{
	size_t urlen;
	struct cache_node *node;

	urlen = strlen(url);
	node = find_node(tbl, url, urlen);
	if (node)
		return node;

	node = pzalloc(sizeof(struct cache_node));
	node->map.url = pstrdup(url);
	node->map.path = create_path(tbl);
	if (!node->map.path) {
		free(node->map.url);
		free(node);
		return NULL;
	}
	HASH_ADD_KEYPTR(hh, tbl->nodes, node->map.url, urlen, node);

	return node;
}

/* @uri is either a caRepository or a rpkiNotify */
static struct cache_node *
do_refresh(struct cache_table *tbl, char const *uri)
{
	struct cache_node *node;

	if (!tbl->enabled)
		return NULL;

	pr_val_debug("Trying %s (online)...", uri);

	node = provide_node(tbl, uri);
	if (!node)
		return NULL;

	if (!node->fresh) {
		node->fresh = true;
		node->dlerr = tbl->download(node);
	}

	pr_val_debug(node->dlerr ? "Refresh failed." : "Refresh succeeded.");
	return node;
}

static struct cache_node *
get_fallback(char const *caRepository)
{
	struct cache_node *node;

	pr_val_debug("Retrieving %s fallback...", caRepository);
	node = find_node(&cache.fallback, caRepository, strlen(caRepository));
	pr_val_debug(node ? "Fallback found." : "Fallback unavailable.");

	return node;
}

/* Do not free nor modify the result. */
char *
cache_refresh_url(char const *url)
{
	struct cache_node *node = NULL;

	// XXX mutex
	// XXX review result signs
	// XXX Normalize @url

	if (url_is_https(url))
		node = do_refresh(&cache.https, url);
	else if (url_is_rsync(url))
		node = do_refresh(&cache.rsync, url);

	// XXX Maybe strdup path so the caller can't corrupt our string
	return node ? node->map.path : NULL;
}

/* Do not free nor modify the result. */
char *
cache_fallback_url(char const *url)
{
	struct cache_node *node;
	node = find_node(&cache.fallback, url, strlen(url));
	return node ? node->map.path : NULL;
}

/*
 * Attempts to refresh the RPP described by @sias, returns the resulting
 * repository's mapping.
 *
 * XXX Need to normalize the sias.
 * XXX Fallback only if parent is fallback
 */
struct cache_cage *
cache_refresh_sias(struct sia_uris *sias)
{
	struct cache_cage *cage;
	struct cache_node *node;

	// XXX Make sure somewhere validates rpkiManifest matches caRepository.
	// XXX mutex
	// XXX review result signs
	// XXX normalize rpkiNotify & caRepository?
	// XXX do module if rsync

	cage = pzalloc(sizeof(struct cache_cage));
	cage->fallback = get_fallback(sias->caRepository);

	if (sias->rpkiNotify) {
		node = do_refresh(&cache.rrdp, sias->rpkiNotify);
		if (node && !node->dlerr) {
			cage->refresh = node;
			return cage; /* RRDP + optional fallback happy path */
		}
	}

	node = do_refresh(&cache.rsync, sias->caRepository);
	if (node && !node->dlerr) {
		cage->refresh = node;
		return cage; /* rsync + optional fallback happy path */
	}

	if (cage->fallback == NULL) {
		free(cage);
		return NULL;
	}

	return cage; /* fallback happy path */
}

char const *
node2file(struct cache_node *node, char const *url)
{
	if (node == NULL)
		return NULL;
	return (node->rrdp)
	    ? /* RRDP  */ rrdp_file(node->rrdp, url)
	    : /* rsync */ join_paths(node->map.path, url + RPKI_SCHEMA_LEN); // XXX wrong; need to get the module.
}

char const *
cage_map_file(struct cache_cage *cage, char const *url)
{
	char const *file;

	file = node2file(cage->refresh, url);
	if (!file)
		file = node2file(cage->fallback, url);

	return file;
}

/* Returns true if previously enabled */
bool
cage_disable_refresh(struct cache_cage *cage)
{
	bool enabled = (cage->refresh != NULL);
	cage->refresh = NULL;
	return enabled;
}

static void
cachent_print(struct cache_node *node)
{
	if (!node)
		return;

	printf("\t%s (%s): ", node->map.url, node->map.path);
	if (node->fresh)
		printf("fresh (errcode %d)", node->dlerr);
	else
		printf("stale");
	printf("\n");
}

static void
table_print(struct cache_table *tbl)
{
	struct cache_node *node, *tmp;

	printf("%s (%s):", tbl->name, tbl->enabled ? "enabled" : "disabled");
	HASH_ITER(hh, tbl->nodes, node, tmp)
		cachent_print(node);
}

void
cache_print(void)
{
	table_print(&cache.rsync);
	table_print(&cache.https);
	table_print(&cache.rrdp);
	table_print(&cache.fallback);
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

static void
remove_abandoned(void)
{
	// XXX no need to recurse anymore.
	/*
	char *rootpath;

	rootpath = join_paths(config_get_local_repository(), "rsync");

	nftw_root = cache.rsync;
	nftw(rootpath, nftw_remove_abandoned, 32, FTW_DEPTH | FTW_PHYS); // XXX

	strcpy(rootpath + strlen(rootpath) - 5, "https");

	nftw_root = cache.https;
	nftw(rootpath, nftw_remove_abandoned, 32, FTW_DEPTH | FTW_PHYS); // XXX

	free(rootpath);
	*/
}

static void
remove_orphaned(struct cache_table *table, struct cache_node *node)
{
	if (file_exists(node->map.path) == ENOENT) {
		pr_op_debug("Missing file; deleting node: %s", node->map.path);
		delete_node(table, node);
	}
}

static void
cache_foreach(void (*cb)(struct cache_table *, struct cache_node *))
{
	struct cache_node *node, *tmp;

	HASH_ITER(hh, cache.rsync.nodes, node, tmp)
		cb(&cache.rsync, node);
	HASH_ITER(hh, cache.https.nodes, node, tmp)
		cb(&cache.https, node);
	HASH_ITER(hh, cache.rrdp.nodes, node, tmp)
		cb(&cache.rrdp, node);
	HASH_ITER(hh, cache.fallback.nodes, node, tmp)
		cb(&cache.fallback, node);
}

/*
 * Deletes unknown and old untraversed cached files, writes metadata into XML.
 */
static void
cleanup_cache(void)
{
	// XXX Review

	pr_op_debug("Cleaning up temporal files.");
	cleanup_tmp();

	pr_op_debug("Cleaning up old abandoned and unknown cache files.");
	remove_abandoned();

	pr_op_debug("Cleaning up orphaned nodes.");
	cache_foreach(remove_orphaned);
}

void
cache_commit(void)
{
	cleanup_cache();
	write_tal_json();
	cache_foreach(delete_node);
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
	free(sias->crldp);
	free(sias->caIssuers);
	free(sias->signedObject);
}
