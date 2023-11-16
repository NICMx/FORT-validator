#include "cache/local_cache.h"

#include <time.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "json_util.h"
#include "log.h"
#include "rrdp.h"
#include "thread_var.h"
#include "data_structure/path_builder.h"
#include "data_structure/uthash.h"
#include "http/http.h"
#include "rsync/rsync.h"

/*
 * Please note: Some of the functions in this module (the ones that have to do
 * with jansson, both inside and outside of it) are recursive.
 *
 * This is fine. Infinite recursion is prevented through path_builder's
 * MAX_CAPACITY (which is currently defined as 4096), which has to be done
 * anyway.
 *
 * And given that you need at least one character and one slash per directory
 * level, the maximum allowed recursion level is 2048, which happens to align
 * with jansson's JSON_PARSER_MAX_DEPTH. (Which is also something we can't
 * change.)
 *
 * FIXME test max recursion
 */

#define TAGNAME_BN		"basename"
#define TAGNAME_DIRECT		"direct-download"
#define TAGNAME_ERROR		"latest-result"
#define TAGNAME_TSATTEMPT	"attempt-timestamp"
#define TAGNAME_SUCCESS		"successful-download"
#define TAGNAME_TSSUCCESS	"success-timestamp"
#define TAGNAME_FILE		"is-file"
#define TAGNAME_CHILDREN	"children"

/*
 * Have we ever attempted to download this directly?
 * Otherwise we actually downloaded a descendant.
 *
 * Directly downloaded nodes need to be retained, along with their ancestors.
 * If the download was successful, they should never have children (as this
 * would be redundant), though their directory counterparts probably will.
 */
#define CNF_DIRECT (1 << 0)
/* Has it downloaded successfully at some point? */
#define CNF_SUCCESS (1 << 1)
/* Has it been traversed during the current cleanup? */
#define CNF_FOUND (1 << 2)
/*
 * If enabled, node represents a file. Otherwise, node is a directory.
 * Only valid on HTTPs trees; we never know what rsync downloads.
 */
#define CNF_FILE (1 << 3)

struct cache_node {
	char *basename; /* Simple file name, parents not included */

	/* CNF_* */
	int flags;
	/*
	 * Last successful download timestamp.
	 * (Only if CNF_DIRECT & CNF_SUCCESS.)
	 * FIXME Intended to later decide whether a file should be deleted,
	 * when the cache is running out of space.
	 */
	time_t ts_success;
	/*
	 * Last download attempt timestamp. (Only if CNF_DIRECT.)
	 * Decides whether the file needs to be updated.
	 */
	time_t ts_attempt;
	/* Last download attempt's result status. (Only if CNF_DIRECT) */
	int error;

	struct cache_node *parent; /* Simple pointer */
	struct cache_node *children; /* Hash table */

	UT_hash_handle hh; /* Hash table hook */
};

struct rpki_cache {
	char *tal;
	struct cache_node *rsync;
	struct cache_node *https;
	time_t startup_time; /* When we started the last validation */
};

static struct cache_node *
add_child(struct cache_node *parent, char const *basename)
{
	struct cache_node *child;
	char *key;
	size_t keylen;

	child = pzalloc(sizeof(struct cache_node));
	child->basename = pstrdup(basename);
	child->parent = parent;

	key = child->basename;
	keylen = strlen(key);

	HASH_ADD_KEYPTR(hh, parent->children, key, keylen, child);

	return child;
}

static struct cache_node *
init_root(struct cache_node *root, char const *name)
{
	if (root != NULL)
		return root;

	root = pzalloc(sizeof(struct cache_node));
	root->basename = pstrdup(name);

	return root;
}

static void
__delete_node(struct cache_node *node)
{
	if (node->parent != NULL)
		HASH_DEL(node->parent->children, node);
	free(node->basename);
	free(node);
}

static void
delete_node(struct cache_node *node)
{
	struct cache_node *parent;

	if (node == NULL)
		return;

	if (node->parent != NULL) {
		HASH_DEL(node->parent->children, node);
		node->parent = NULL;
	}

	do {
		while (node->children != NULL)
			node = node->children;
		parent = node->parent;
		__delete_node(node);
		node = parent;
	} while (node != NULL);
}

static int
get_metadata_json_filename(char const *tal, char **filename)
{
	struct path_builder pb;
	int error;

	error = pb_init_cache(&pb, tal, "metadata.json");
	if (error)
		return error;

	*filename = pb.string;
	return 0;
}

static struct cache_node *
json2node(json_t *json, struct cache_node *parent)
{
	struct cache_node *node, *child;
	char const *string;
	bool boolean;
	json_t *jchild;
	size_t c;
	int error;

	if (json == NULL)
		return NULL;

	node = pzalloc(sizeof(struct cache_node));

	error = json_get_str(json, TAGNAME_BN, &string);
	if (error) {
		if (error > 0)
			pr_op_err("Node is missing the '" TAGNAME_BN "' tag.");
		goto cancel;
	}
	node->basename = pstrdup(string);

	if (json_get_bool(json, TAGNAME_DIRECT, &boolean) < 0)
		goto cancel;
	if (boolean) {
		node->flags |= CNF_DIRECT;
		if (json_get_int(json, TAGNAME_ERROR, &node->error) < 0)
			goto cancel;

		if (json_get_ts(json, TAGNAME_TSATTEMPT, &node->ts_attempt) < 0)
			goto cancel;

		if (json_get_bool(json, TAGNAME_SUCCESS, &boolean) < 0)
			goto cancel;
		if (boolean) {
			node->flags |= CNF_SUCCESS;
			if (json_get_ts(json, TAGNAME_TSSUCCESS, &node->ts_success) < 0)
				goto cancel;
		}
	}

	if (json_get_bool(json, TAGNAME_FILE, &boolean) < 0)
		goto cancel;
	if (boolean)
		node->flags |= CNF_FILE;

	if (json_get_array(json, "children", &jchild) < 0)
		goto cancel;
	for (c = 0; c < json_array_size(jchild); c++) {
		child = json2node(json_array_get(jchild, c), node);
		if (child != NULL)
			HASH_ADD_KEYPTR(hh, node->children, child->basename,
			    strlen(child->basename), child);
	}

	node->parent = parent;
	pr_op_debug("Node '%s' successfully loaded from metadata.json.",
	    node->basename);
	return node;

cancel:
	delete_node(node);
	return NULL;
}

static void
load_metadata_json(struct rpki_cache *cache)
{
	char *filename;
	json_t *root;
	json_error_t jerror;
	struct cache_node *node;
	size_t d;

	/*
	 * Note: Loading metadata.json is one of few things Fort can fail at
	 * without killing itself. It's just a cache of a cache.
	 */

	if (get_metadata_json_filename(cache->tal, &filename) != 0)
		return;

	root = json_load_file(filename, 0, &jerror);

	if (root == NULL) {
		if (json_error_code(&jerror) == json_error_cannot_open_file) {
			pr_op_debug("%s does not exist.", filename);
		} else {
			pr_op_err("Json parsing failure at %s (%d:%d): %s",
			    filename, jerror.line, jerror.column, jerror.text);
		}
		goto end;
	}
	if (json_typeof(root) != JSON_ARRAY) {
		pr_op_err("The root tag of %s is not an array.", filename);
		goto end;
	}

	for (d = 0; d < json_array_size(root); d++) {
		node = json2node(json_array_get(root, d), NULL);
		if (node == NULL)
			continue;
		else if (strcasecmp(node->basename, "rsync") == 0)
			cache->rsync = node;
		else if (strcasecmp(node->basename, "https") == 0)
			cache->https = node;
		else {
			pr_op_warn("%s: Ignoring unrecognized json node '%s'.",
			    filename, node->basename);
			delete_node(node);
		}
	}

end:
	free(filename);
	json_decref(root);
}

static json_t *
node2json(struct cache_node *node)
{
	json_t *json, *children, *jchild;
	struct cache_node *child, *tmp;
	int cnf;

	json = json_object();
	if (json == NULL) {
		pr_op_err("json object allocation failure.");
		return NULL;
	}

	if (json_add_str(json, TAGNAME_BN, node->basename))
		goto cancel;

	cnf = node->flags & CNF_DIRECT;
	if (cnf) {
		if (json_add_bool(json, TAGNAME_DIRECT, cnf))
			goto cancel;
		if (json_add_int(json, TAGNAME_ERROR, node->error))
			goto cancel;
		if (json_add_date(json, TAGNAME_TSATTEMPT, node->ts_attempt))
			goto cancel;
		cnf = node->flags & CNF_SUCCESS;
		if (cnf) {
			if (json_add_bool(json, TAGNAME_SUCCESS, cnf))
				goto cancel;
			if (json_add_date(json, TAGNAME_TSSUCCESS, node->ts_success))
				goto cancel;
		}
	}
	cnf = node->flags & CNF_FILE;
	if (cnf && json_add_bool(json, TAGNAME_FILE, cnf))
		goto cancel;

	if (node->children != NULL) {
		children = json_array();
		if (children == NULL) {
			pr_op_err("json array allocation failure.");
			return NULL;
		}

		if (json_object_set_new(json, TAGNAME_CHILDREN, children)) {
			pr_op_err("Cannot push children array into json node; unknown cause.");
			goto cancel;
		}

		HASH_ITER(hh, node->children, child, tmp) {
			jchild = node2json(child);
			if (jchild == NULL)
				goto cancel; /* Error msg already printed */
			if (json_array_append(children, jchild)) {
				pr_op_err("Cannot push child into json node; unknown cause.");
				goto cancel;
			}
		}
	}

	return json;

cancel:
	json_decref(json);
	return NULL;
}

static int
append_node(json_t *root, struct cache_node *node, char const *name)
{
	json_t *child;

	if (node == NULL)
		return 0;
	child = node2json(node);
	if (child == NULL)
		return -1;
	if (json_array_append(root, child)) {
		pr_op_err("Cannot push %s json node into json root; unknown cause.",
		    name);
		return -1;
	}

	return 0;
}

static json_t *
build_metadata_json(struct rpki_cache *cache)
{
	json_t *root;

	root = json_array();
	if (root == NULL) {
		pr_op_err("json root allocation failure.");
		return NULL;
	}

	if (append_node(root, cache->rsync, "rsync")
	    || append_node(root, cache->https, "https")) {
		json_decref(root);
		return NULL;
	}

	return root;
}

static void
write_metadata_json(struct rpki_cache *cache)
{
	struct json_t *json;
	char *filename;

	json = build_metadata_json(cache);
	if (json == NULL)
		return;

	if (get_metadata_json_filename(cache->tal, &filename) != 0)
		return;

	if (json_dump_file(json, filename, JSON_COMPACT))
		pr_op_err("Unable to write metadata.json; unknown cause.");

	free(filename);
	json_decref(json);
}

struct rpki_cache *
cache_create(char const *tal)
{
	struct rpki_cache *cache;

	cache = pmalloc(sizeof(struct rpki_cache));
	cache->tal = pstrdup(tal);
	cache->rsync = NULL;
	cache->https = NULL;
	cache->startup_time = time(NULL);
	if (cache->startup_time == ((time_t) -1))
		pr_crit("time(NULL) returned -1");

	load_metadata_json(cache);

	return cache;
}

void
cache_destroy(struct rpki_cache *cache)
{
	write_metadata_json(cache);
	free(cache->tal);
	delete_node(cache->rsync);
	delete_node(cache->https);
	free(cache);
}

static int
delete_node_file(struct rpki_cache *cache, struct cache_node *node,
    bool is_file)
{
	struct path_builder pb;
	struct cache_node *cursor;
	int error;

	pb_init(&pb);
	for (cursor = node; cursor != NULL; cursor = cursor->parent) {
		error = pb_append(&pb, cursor->basename);
		if (error)
			goto cancel;
	}
	error = pb_append(&pb, cache->tal);
	if (error)
		goto cancel;
	error = pb_append(&pb, config_get_local_repository());
	if (error)
		goto cancel;
	pb_reverse(&pb);

	if (is_file) {
		if (remove(pb.string) != 0) {
			error = errno;
			pr_val_err("Cannot override file '%s': %s",
			    pb.string, strerror(error));
		}
	} else {
		error = file_rm_rf(pb.string);
		pr_val_err("Cannot override directory '%s': %s",
		    pb.string, strerror(error));
	}

	pb_cleanup(&pb);
	return error;

cancel:
	pb_cleanup(&pb);
	return error;
}

static bool
was_recently_downloaded(struct rpki_cache *cache, struct cache_node *node)
{
	return (node->flags & CNF_DIRECT) &&
	       (cache->startup_time <= node->ts_attempt);
}

static void
drop_children(struct cache_node *node)
{
	struct cache_node *child, *tmp;

	HASH_ITER(hh, node->children, child, tmp)
		delete_node(child);
}

static char *
uri2luri(struct rpki_uri *uri)
{
	char const *luri;

	luri = uri_get_local(uri) + strlen(config_get_local_repository());
	while (luri[0] == '/')
		luri++;

	return pstrdup(luri);
}

/* Returns 0 if the file exists, nonzero otherwise. */
static int
cache_check(struct rpki_uri *uri)
{
	struct stat meta;
	int error;

	if (stat(uri_get_local(uri), &meta) != 0) {
		error = errno;
		pr_val_debug("Offline mode, file is not cached.");
		return error;
	}

	pr_val_debug("Offline mode, file is cached.");
	return 0;
}

/**
 * @changed only on HTTP.
 */
int
cache_download(struct rpki_cache *cache, struct rpki_uri *uri, bool *changed)
{
	char *luri;
	char *token;
	char *saveptr;
	struct cache_node *node, *child;
	bool recursive;
	int error;

	if (changed != NULL)
		*changed = false;
	luri = uri2luri(uri);

	token = strtok_r(luri, "/", &saveptr);
	if (strcmp(token, cache->tal) != 0)
		pr_crit("Expected TAL %s for path %s.", cache->tal, uri_get_local(uri));

	token = strtok_r(NULL, "/", &saveptr);
	switch (uri_get_type(uri)) {
	case UT_RSYNC:
		if (strcmp(token, "rsync") != 0)
			return pr_val_err("Path is not rsync: %s", uri_get_local(uri));
		if (!config_get_rsync_enabled()) {
			error = cache_check(uri);
			goto end;
		}
		node = cache->rsync = init_root(cache->rsync, "rsync");
		recursive = true;
		break;
	case UT_HTTPS:
		if (strcmp(token, "https") != 0)
			return pr_val_err("Path is not HTTPS: %s", uri_get_local(uri));
		if (!config_get_http_enabled()) {
			error = cache_check(uri);
			goto end;
		}
		node = cache->https = init_root(cache->https, "https");
		recursive = false;
		break;
	default:
		pr_crit("Unexpected URI type: %d", uri_get_type(uri));
	}

	while ((token = strtok_r(NULL, "/", &saveptr)) != NULL) {
		if (node->flags & CNF_FILE) {
			/* node used to be a file, now it's a dir. */
			delete_node_file(cache, node, true);
			node->flags = 0;
		}

		HASH_FIND_STR(node->children, token, child);

		if (child == NULL) {
			/* Create child */
			do {
				node = add_child(node, token);
				token = strtok_r(NULL, "/", &saveptr);
			} while (token != NULL);
			goto download;
		}

		if (recursive) {
			if (was_recently_downloaded(cache, child) &&
			    !child->error) {
				error = 0;
				goto end;
			}
		}

		node = child;
	}

	if (was_recently_downloaded(cache, node)) {
		error = node->error;
		goto end;
	}

	if (!recursive && !(node->flags & CNF_FILE)) {
		/* node used to be a dir, now it's a file. */
		delete_node_file(cache, node, false);
	}

download:
	switch (uri_get_type(uri)) {
	case UT_RSYNC:
		error = rsync_download(uri);
		break;
	case UT_HTTPS:
		error = http_download(uri, changed);
		break;
	default:
		pr_crit("Unexpected URI type: %d", uri_get_type(uri));
	}

	node->error = error;
	node->flags = CNF_DIRECT;
	node->ts_attempt = time(NULL);
	if (node->ts_attempt == ((time_t) -1))
		pr_crit("time(NULL) returned -1");
	if (!error) {
		node->flags |= CNF_SUCCESS | (recursive ? 0 : CNF_FILE);
		node->ts_success = node->ts_attempt;
	}
	drop_children(node);

end:
	free(luri);
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
	if (!(new->flags & CNF_SUCCESS))
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

	if (old->error && !new->error)
		return new;
	if (!old->error && new->error)
		return old;
	return (difftime(old->ts_success, new->ts_success) < 0) ? new : old;
}

static struct cache_node *
find_node(struct rpki_cache *cache, struct rpki_uri *uri)
{
	char *luri, *token, *saveptr;
	struct cache_node *parent, *node;
	bool recursive;
	struct cache_node *result;

	luri = uri2luri(uri);
	node = NULL;
	result = NULL;

	token = strtok_r(luri, "/", &saveptr);
	if (strcmp(token, cache->tal) != 0)
		pr_crit("Expected TAL %s for path %s.", cache->tal, uri_get_local(uri));

	token = strtok_r(NULL, "/", &saveptr);
	switch (uri_get_type(uri)) {
	case UT_RSYNC:
		parent = cache->rsync;
		recursive = true;
		break;
	case UT_HTTPS:
		parent = cache->https;
		recursive = false;
		break;
	default:
		pr_crit("Unexpected URI type: %d", uri_get_type(uri));
	}

	if (parent == NULL)
		goto end;

	while ((token = strtok_r(NULL, "/", &saveptr)) != NULL) {
		HASH_FIND_STR(parent->children, token, node);
		if (node == NULL)
			goto end;
		if (recursive && (node->flags & CNF_DIRECT))
			result = choose_better(result, node);
		parent = node;
	}

	if (!recursive && (node != NULL) && (node->flags & CNF_DIRECT))
		result = choose_better(result, node);

end:
	free(luri);
	return result;
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
	struct uri_and_node cursor;

	ARRAYLIST_FOREACH(uris, uri) {
		cursor.uri = *uri;
		cursor.node = find_node(cache, cursor.uri);
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

static void
__cache_print(struct cache_node *node, unsigned int tabs)
{
	unsigned int i;
	struct cache_node *child, *tmp;

	if (node == NULL)
		return;

	for (i = 0; i < tabs; i++)
		printf("\t");
	printf("%s: %sdirect %ssuccess %sfile error:%d\n",
	    node->basename,
	    (node->flags & CNF_DIRECT) ? "" : "!",
	    (node->flags & CNF_SUCCESS) ? "" : "!",
	    (node->flags & CNF_FILE) ? "" : "!",
	    node->error);
	HASH_ITER(hh, node->children, child, tmp)
		__cache_print(child, tabs + 1);
}

void
cache_print(struct rpki_cache *cache)
{
	__cache_print(cache->rsync, 0);
	__cache_print(cache->https, 0);
}

/*
 * @force: ignore nonexistent files
 */
static void
pb_rm_r(struct path_builder *pb, char const *filename, bool force)
{
	int error;

	error = file_rm_rf(pb->string);
	if (error && !force)
		pr_op_err("Cannot delete %s: %s", pb->string, strerror(error));
}

enum ctt_status {
	CTTS_STILL,
	CTTS_UP,
	CTTS_DOWN,
};

struct cache_tree_traverser {
	struct rpki_cache *cache;
	struct cache_node **root;
	struct cache_node *next;
	struct path_builder *pb;
	enum ctt_status status;
};

static void
ctt_init(struct cache_tree_traverser *ctt, struct rpki_cache *cache,
    struct cache_node **root, struct path_builder *pb)
{
	struct cache_node *node;

	node = *root;
	if (node != NULL && (pb_append(pb, "a") != 0))
		node = node->parent;

	ctt->cache = cache;
	ctt->root = root;
	ctt->next = node;
	ctt->pb = pb;
	ctt->status = CTTS_DOWN;
}

static bool
is_node_fresh(struct rpki_cache *cache, struct cache_node *node)
{
	return was_recently_downloaded(cache, node) && !node->error;
}

/*
 * Assumes @node has not been added to the pb.
 */
static struct cache_node *
ctt_delete(struct cache_tree_traverser *ctt, struct cache_node *node)
{
	struct cache_node *parent, *sibling;

	sibling = node->hh.next;
	parent = node->parent;

	delete_node(node);

	if (sibling != NULL) {
		ctt->status = CTTS_DOWN;
		return sibling;
	}

	if (parent != NULL) {
		ctt->status = CTTS_UP;
		return parent;
	}

	*ctt->root = NULL;
	return NULL;
}

/*
 * Assumes @node is not NULL, has yet to be traversed, and is already included
 * in the pb.
 */
static struct cache_node *
go_up(struct cache_tree_traverser *ctt, struct cache_node *node)
{
	if (node->children == NULL && !is_node_fresh(ctt->cache, node)) {
		pb_pop(ctt->pb, true);
		return ctt_delete(ctt, node);
	}

	ctt->status = CTTS_STILL;
	return node;
}

static struct cache_node *
find_first_viable_child(struct cache_tree_traverser *ctt,
    struct cache_node *node)
{
	struct cache_node *child, *tmp;

	HASH_ITER(hh, node->children, child, tmp) {
		if (pb_append(ctt->pb, child->basename) == 0)
			return child;
		delete_node(child); /* Unviable */
	}

	return NULL;
}

/*
 * Assumes @node is not NULL, has yet to be traversed, and has not yet been
 * added to the pb.
 */
static struct cache_node *
go_down(struct cache_tree_traverser *ctt, struct cache_node *node)
{
	struct cache_node *child;

	if (pb_append(ctt->pb, node->basename) != 0)
		return ctt_delete(ctt, node);

	do {
		if (is_node_fresh(ctt->cache, node)) {
			drop_children(node);
			ctt->status = CTTS_STILL;
			return node;
		}

		child = find_first_viable_child(ctt, node);
		if (child == NULL) {
			/* Welp; stale and no children. */
			ctt->status = CTTS_UP;
			return node;
		}

		node = child;
	} while (true);
}

/*
 * - Depth-first, post-order, non-recursive, safe [1] traversal.
 * - However, deletion is the only allowed modification during the traversal.
 * - If the node is fresh [2], it will have no children.
 *   (Because they would be redundant.)
 *   (Childless nodes do not imply corresponding childless directories.)
 * - If the node is not fresh, it WILL have children.
 *   (Stale [3] nodes are always sustained by fresh descendant nodes.)
 * - The ctt will automatically clean up unviable [4] and unsustained stale
 *   nodes during the traversal, caller doesn't have to worry about them.
 * - The ctt's pb will be updated at all times, caller should not modify the
 *   string.
 *
 * [1] Safe = caller can delete the returned node via delete_node(), during
 *     iteration.
 * [2] Fresh = Mapped to a file or directory that was downloaded/updated
 *     successfully at some point since the beginning of the iteration.
 * [3] Stale = Not fresh
 * [4] Unviable = Node's path is too long, ie. cannot be mapped to a cache file.
 */
static struct cache_node *
ctt_next(struct cache_tree_traverser *ctt)
{
	struct cache_node *next = ctt->next;

	if (next == NULL)
		return NULL;

	pb_pop(ctt->pb, true);

	do {
		if (ctt->status == CTTS_DOWN)
			next = go_down(ctt, next);
		else if (ctt->status == CTTS_UP)
			next = go_up(ctt, next);

		if (next == NULL) {
			ctt->next = NULL;
			return NULL;
		}
	} while (ctt->status != CTTS_STILL);

	if (next->hh.next != NULL) {
		ctt->next = next->hh.next;
		ctt->status = CTTS_DOWN;
	} else {
		ctt->next = next->parent;
		ctt->status = CTTS_UP;
	}

	return next;
}

static void
cleanup_tree(struct rpki_cache *cache, struct cache_node **root,
    char const *treename)
{
	struct cache_tree_traverser ctt;
	struct path_builder pb;
	struct stat meta;
	DIR *dir;
	struct dirent *file;
	struct cache_node *node, *child, *tmp;
	int error;

	if (pb_init_cache(&pb, cache->tal, NULL) != 0)
		return;

	ctt_init(&ctt, cache, root, &pb);

	while ((node = ctt_next(&ctt)) != NULL) {
		if (stat(pb.string, &meta) != 0) {
			error = errno;
			if (error == ENOENT) {
				/* Node exists but file doesn't: Delete node */
				delete_node(node);
				continue;
			}

			pr_op_err("Cannot clean up '%s'; stat() returned errno %d: %s",
			    pb.string, error, strerror(error));
			continue;
		}

		if (!node->children)
			continue; /* Node represents file, file does exist. */
		/* Node represents directory. */

		if (!S_ISDIR(meta.st_mode)) {
			/* File is not a directory; welp. */
			remove(pb.string);
			delete_node(node);
			continue;
		}

		dir = opendir(pb.string);
		if (dir == NULL) {
			error = errno;
			pr_op_err("Cannot clean up '%s'; S_ISDIR() but !opendir(): %s",
			    pb.string, strerror(error));
			continue; /* AAAAAAAAAAAAAAAAAH */
		}

		FOREACH_DIR_FILE(dir, file) {
			if (S_ISDOTS(file))
				continue;

			HASH_FIND_STR(node->children, file->d_name, child);
			if (child != NULL) {
				child->flags |= CNF_FOUND;
			} else {
				/* File child's node does not exist: Delete. */
				if (pb_append(&pb, file->d_name) == 0) {
					pb_rm_r(&pb, file->d_name, false);
					pb_pop(&pb, true);
				}
			}
		}

		error = errno;
		closedir(dir);
		if (error) {
			pr_op_err("Cannot clean up directory (basename is '%s'): %s",
			    node->basename, strerror(error));
			HASH_ITER(hh, node->children, child, tmp)
				child->flags &= ~CNF_FOUND;
			continue; /* AAAAAAAAAAAAAAAAAH */
		}

		HASH_ITER(hh, node->children, child, tmp) {
			if (child->flags & CNF_FOUND) {
				/*
				 * File child still exists, which means there's
				 * at least one active descendant.
				 * Clean the flag and keep the node.
				 */
				child->flags &= ~CNF_FOUND;
			} else {
				/* Node child's file does not exist: Delete. */
				delete_node(child);
			}
		}

		if (node->children == NULL) {
			/* Node is inactive and we rm'd its children: Delete. */
			pb_rm_r(&pb, node->basename, false);
			delete_node(node);
		}
	}

	if ((*root) == NULL && pb_append(&pb, treename) == 0)
		pb_rm_r(&pb, treename, true);

	pb_cleanup(&pb);
}

void
cache_cleanup(void)
{
	struct rpki_cache *cache = validation_cache(state_retrieve());
	cleanup_tree(cache, &cache->rsync, "rsync");
	cleanup_tree(cache, &cache->https, "https");
	write_metadata_json(cache);
}
