#include "cache/local_cache.h"

#include <time.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"
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

/* FIXME needs locking */

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

static struct cache_node *rsync;
static struct cache_node *https;

static time_t startup_time; /* When we started the last validation */

/* Minimizes multiple evaluation */
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

	if (node == rsync)
		rsync = NULL;
	else if (node == https)
		https = NULL;
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
get_metadata_json_filename(char **filename)
{
	struct path_builder pb;
	int error;

	error = pb_init_cache(&pb, "metadata.json");
	if (error)
		return error;

	*filename = pb.string;
	return 0;
}

static int
json_tt_value(struct json_t const *json, time_t *result)
{
	char const *str;
	struct tm tm;
	time_t tmp;

	if (json == NULL)
		return -1;
	str = json_string_value(json);
	if (str == NULL)
		return -1;
	str = strptime(str, "%FT%T%z", &tm);
	if (str == NULL || *str != 0)
		return -1;
	tmp = mktime(&tm);
	if (tmp == ((time_t) -1))
		return -1;

	*result = tmp;
	return 0;
}

static struct cache_node *
json2node(json_t *json, struct cache_node *parent)
{
	struct cache_node *node, *child;
	char const *string;
	json_t *jchild;
	size_t c;

	if (json == NULL)
		return NULL;

	node = pzalloc(sizeof(struct cache_node));

	string = json_string_value(json_object_get(json, "basename"));
	if (string == NULL) {
		pr_op_warn("Tag 'basename' of a metadata.json's download node cannot be parsed as a string; skipping.");
		goto cancel;
	}
	node->basename = pstrdup(string);

	jchild = json_object_get(json, "flags");
	if (!json_is_integer(jchild)) {
		pr_op_warn("Tag 'flags' of metadata.json's download node '%s' cannot be parsed as an integer; skipping.",
		    node->basename);
		goto cancel;
	}
	node->flags = json_integer_value(jchild);

	if (json_tt_value(json_object_get(json, "ts_success"), &node->ts_success)) {
		pr_op_warn("Tag 'success' of metadata.json's download node '%s' cannot be parsed as a date; skipping.",
		    node->basename);
		goto cancel;
	}

	if (json_tt_value(json_object_get(json, "ts_attempt"), &node->ts_attempt)) {
		pr_op_warn("Tag 'attempt' of metadata.json's download node '%s' cannot be parsed as a date; skipping.",
		    node->basename);
		goto cancel;
	}

	jchild = json_object_get(json, "error");
	if (!json_is_integer(jchild)) {
		pr_op_warn("Tag 'error' of metadata.json's download node '%s' cannot be parsed as an integer; skipping.",
		    node->basename);
		goto cancel;
	}
	node->error = json_integer_value(jchild);

	jchild = json_object_get(json, "children");
	if (jchild != NULL && !json_is_array(jchild)) {
		pr_op_warn("Tag 'children' of metadata.json's download node '%s' cannot be parsed as an array; skipping.",
		    node->basename);
		goto cancel;
	}

	for (c = 0; c < json_array_size(jchild); c++) {
		child = json2node(json_array_get(jchild, c), node);
		if (child == NULL)
			goto cancel;
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
load_metadata_json(void)
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

	if (get_metadata_json_filename(&filename) != 0)
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
			rsync = node;
		else if (strcasecmp(node->basename, "https") == 0)
			https = node;
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

int
cache_prepare(void)
{
	struct path_builder pb;
	int error;

	startup_time = time(NULL);
	if (startup_time == ((time_t) -1))
		pr_crit("time(NULL) returned -1");

	if (rsync == NULL)
		load_metadata_json();

	error = pb_init_cache(&pb, "tmp");
	if (error)
		return error;
	error = create_dir_recursive(pb.string, true);
	pb_cleanup(&pb);
	return error;
}

static int
delete_node_file(struct cache_node *node, bool is_file)
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
was_recently_downloaded(struct cache_node *node)
{
	return (node->flags & CNF_DIRECT) && (startup_time <= node->ts_attempt);
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

/**
 * @changed only on HTTP.
 */
int
cache_download(struct rpki_uri *uri, bool *changed)
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

	switch (uri_get_type(uri)) {
	case UT_RSYNC:
		node = rsync = init_root(rsync, "rsync");
		recursive = true;
		break;
	case UT_HTTPS:
		node = https = init_root(https, "https");
		recursive = false;
		break;
	default:
		pr_crit("Unexpected URI type: %d", uri_get_type(uri));
	}

	while ((token = strtok_r(NULL, "/", &saveptr)) != NULL) {
		if (node->flags & CNF_FILE) {
			/* node used to be a file, now it's a dir. */
			delete_node_file(node, true);
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
			if (was_recently_downloaded(child) && !child->error) {
				error = 0;
				goto end;
			}
		}

		node = child;
	}

	if (was_recently_downloaded(node)) {
		error = node->error;
		goto end;
	}

	if (!recursive && !(node->flags & CNF_FILE)) {
		/* node used to be a dir, now it's a file. */
		delete_node_file(node, false);
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

static struct cache_node *
find_uri(struct rpki_uri *uri)
{
	char *luri, *token, *saveptr;
	struct cache_node *parent, *node;
	bool recursive;
	struct cache_node *result;

	luri = uri2luri(uri);
	token = strtok_r(luri, "/", &saveptr);
	node = NULL;
	result = NULL;

	switch (uri_get_type(uri)) {
	case UT_RSYNC:
		parent = rsync;
		recursive = true;
		break;
	case UT_HTTPS:
		parent = https;
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
			result = node;
		parent = node;
	}

	if ((node != NULL) && (node->flags & CNF_DIRECT))
		result = node;

end:
	free(luri);
	return result;
}

static unsigned int
get_score(struct cache_node *node)
{
	unsigned int score;

	/*
	 * Highest to lowest priority:
	 *
	 * 1. Recent Success: !error, CNF_SUCCESS, high ts_success.
	 * 2. Old Success: !error, CNF_SUCCESS, low ts_success.
	 * 3. Previous Recent Success: error, CNF_SUCCESS, high ts_success.
	 * 4. Previous Old Success: error, CNF_SUCCESS, old ts_success.
	 * 5. No Success: error, !CNF_SUCCESS (completely unviable)
	 */

	if (node == NULL)
		return 0;

	score = 0;
	if (!node->error)
		score |= (1 << 1);
	if (node->flags & CNF_SUCCESS)
		score |= (1 << 0);
	return score;
}

/*
 * Returns true if @n1's success happened earlier than n2's.
 */
static bool
earlier_success(struct cache_node *n1, struct cache_node *n2)
{
	return difftime(n1->ts_success, n2->ts_success) < 0;
}

struct rpki_uri *
cache_recover(struct uri_list *uris, bool use_rrdp)
{
	struct scr {
		struct rpki_uri *uri;
		struct cache_node *node;
		unsigned int score;
	};

	struct rpki_uri **uri;
	struct scr cursor;
	struct scr best = { 0 };

	ARRAYLIST_FOREACH(uris, uri) {
		cursor.uri = *uri;
		cursor.node = find_uri(cursor.uri);
		cursor.score = get_score(cursor.node);
		if (cursor.score == 0)
			continue;
		if (cursor.score > best.score)
			best = cursor;
		else if (cursor.score == best.score
		      && earlier_success(best.node, cursor.node))
			best = cursor;
	}

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
cache_print(void)
{
	__cache_print(rsync, 0);
	__cache_print(https, 0);
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
	struct cache_node **root;
	struct cache_node *next;
	struct path_builder *pb;
	enum ctt_status status;
};

static void
ctt_init(struct cache_tree_traverser *ctt, struct cache_node **root,
    struct path_builder *pb)
{
	struct cache_node *node;

	node = *root;
	if (node != NULL && (pb_append(pb, "a") != 0))
		node = node->parent;

	ctt->root = root;
	ctt->next = node;
	ctt->pb = pb;
	ctt->status = CTTS_DOWN;
}

static bool
is_node_fresh(struct cache_node *node)
{
	return was_recently_downloaded(node) && !node->error;
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
	if (node->children == NULL && !is_node_fresh(node)) {
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
		if (is_node_fresh(node)) {
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

static void cleanup_tree(struct cache_node **root, char const *treename)
{
	struct cache_tree_traverser ctt;
	struct path_builder pb;
	struct stat meta;
	DIR *dir;
	struct dirent *file;
	struct cache_node *node, *child, *tmp;
	int error;

	if (pb_init_cache(&pb, NULL) != 0)
		return;

	ctt_init(&ctt, root, &pb);

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

static int
tt2json(time_t tt, json_t **result)
{
	char str[32];
	struct tm tmbuffer, *tm;

	memset(&tmbuffer, 0, sizeof(tmbuffer));
	tm = localtime_r(&tt, &tmbuffer);
	if (tm == NULL)
		return errno;
	if (strftime(str, sizeof(str) - 1, "%FT%T%z", tm) == 0)
		return ENOSPC;

	*result = json_string(str);
	return 0;
}

static json_t *
node2json(struct cache_node *node)
{
	json_t *json, *date, *children, *jchild;
	struct cache_node *child, *tmp;
	int error;

	json = json_object();
	if (json == NULL) {
		pr_op_err("json object allocation failure.");
		return NULL;
	}

	if (json_object_set_new(json, "basename", json_string(node->basename))) {
		pr_op_err("Cannot convert string '%s' to json; unknown cause.",
		    node->basename);
		goto cancel;
	}

	if (json_object_set_new(json, "flags", json_integer(node->flags))) {
		pr_op_err("Cannot convert int '%d' to json; unknown cause.",
		    node->flags);
		goto cancel;
	}

	error = tt2json(node->ts_success, &date);
	if (error) {
		pr_op_err("Cannot convert %s's success timestamp to json: %s",
		    node->basename, strerror(error));
		goto cancel;
	}
	if (json_object_set_new(json, "ts_success", date)) {
		pr_op_err("Cannot convert %s's success timestamp to json; unknown cause.",
		    node->basename);
		goto cancel;
	}

	error = tt2json(node->ts_attempt, &date);
	if (error) {
		pr_op_err("Cannot convert %s's attempt timestamp to json: %s",
		    node->basename, strerror(error));
		goto cancel;
	}
	if (json_object_set_new(json, "ts_attempt", date)) {
		pr_op_err("Cannot convert %s's attempt timestamp to json; unknown cause.",
		    node->basename);
		goto cancel;
	}

	if (json_object_set_new(json, "error", json_integer(node->error))) {
		pr_op_err("Cannot convert int '%d' to json; unknown cause.",
		    node->error);
		goto cancel;
	}

	if (node->children != NULL) {
		children = json_array();
		if (children == NULL) {
			pr_op_err("json array allocation failure.");
			return NULL;
		}

		if (json_object_set_new(json, "children", children)) {
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
build_metadata_json(void)
{
	json_t *root;

	root = json_array();
	if (root == NULL) {
		pr_op_err("json root allocation failure.");
		return NULL;
	}

	if (append_node(root, rsync, "rsync")
	    || append_node(root, https, "https")) {
		json_decref(root);
		return NULL;
	}

	return root;
}

static void
write_metadata_json(void)
{
	struct json_t *json;
	char *filename;

	json = build_metadata_json();
	if (json == NULL)
		return;

	if (get_metadata_json_filename(&filename) != 0)
		return;

	if (json_dump_file(json, filename, JSON_COMPACT))
		pr_op_err("Unable to write metadata.json; unknown cause.");

	free(filename);
	json_decref(json);
}

void
cache_cleanup(void)
{
	cleanup_tree(&rsync, "rsync");
	cleanup_tree(&https, "https");
	write_metadata_json();
}

void
cache_teardown(void)
{
	delete_node(rsync);
	rsync = NULL;
	delete_node(https);
	https = NULL;
}
