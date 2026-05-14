#include "cache.h"

#include <fcntl.h>
#include <signal.h>

#include "cachetmp.h"
#include "config.h"
#include "configure_ac.h"
#include "dao/rsync.h"
#include "dao/ta.h"
#include "file.h"
#include "http.h"
#include "json_util.h"
#include "log.h"
#include "rrdp.h"
#include "rsync.h"
#include "task.h"
#include "types/path.h"
#include "types/str.h"
#include "types/uthash.h"

enum node_state {
	/* Refresh nodes: Not downloaded yet (stale) */
	/* Fallback nodes: Queued for commit */
	DLS_OUTDATED = 0,
	/* Refresh nodes: Download in progress */
	/* Fallback nodes: N/A */
	DLS_ONGOING,
	/* Refresh nodes: rsync post-processing in progress */
	/* Fallback nodes: N/A */
	DLS_ONGOING2,
	/* Refresh nodes: Download complete */
	/* Fallback nodes: Committed */
	DLS_FRESH,
};

enum context_type {
	CT_RRDP = 1,
	CT_RSYNC = 2,
	CT_TA = 3,
};

/*
 * This is a delicate structure; pay attention.
 *
 * During the multithreaded stage of the validation cycle, one thread will
 * switch @state from DLS_OUTDATED to DLS_ONGOING, and become the only writer
 * for the given node. Other threads are only allowed to lock, and with the
 * lock, read @state (to find out they shouldn't touch anything else).
 *
 * Most of the cache_node (except @hh and @commits) becomes (effectively)
 * constant when the writer thread upgrades @state to DLS_FRESH.
 *
 * This is intended to allow the cache (ie. this module) to pass the node to the
 * validation code (through rpp_querier) without having to allocate a deep copy
 * (@rrdp can be somewhat large), and to allow the validation code to read-only
 * the node (except @hh and @commits) without having to hold the table mutex.
 *
 * C cannot entirely ensure the node remains constant after it's handed outside;
 * this must be done through careful coding and review.
 */
struct cache_node {
	struct cache_mapping map;

	enum node_state state;
	/* Result code of recent dl attempt (DLS_FRESH only) */
	validation_verdict verdict;
	time_t attempt_ts;	/* Refresh: Dl attempt. Fallback: Commit */
	time_t success_ts;	/* Refresh: Dl success. Fallback: Commit */

	struct {
		enum context_type type;
		/*
		 * Worry about these pointers being NULL, even if type is set.
		 * It happens when the node is new and the download fails.
		 */
		union {
			struct rrdp_ctx *rrdp;
			struct rsync_ctx *rsync;
			struct ta_context *ta;
		} v;
	} ctx;

	UT_hash_handle hh;	/* Hash table hook */
};

typedef validation_verdict (*dl_cb)(struct cache_node *rpp);

/*
 * When concurrency is at play, you need @lock to access @nodes and @seq.
 * @name, @enabled and @download stay constant through the validation.
 *
 * @lock also protects the nodes' @state and @hh, which have additional rules.
 * (See cache_node.)
 */
struct cache_table {
	char *name;
	bool enabled;
	struct cache_sequence seq;
	struct cache_node *nodes;	/* Hash Table */
	pthread_mutex_t lock;
};

static struct rpki_cache {
	struct cache_table rsync;
	struct cache_table https;
} cache;

/* "Is the lockfile ours?" */
static volatile sig_atomic_t lockfile_owned;

struct file_querier {
	struct cache_node *node;
	bool is_refresh;
};

/* Statuses for n-file queriers */
enum rpp_querier_status {
	/* No work made so far */
	CS_START,
	/* Currently checking the most recent RRDP refresh delta */
	CS_RRDP_REFRESH,
	/* Currently checking the rsync refresh */
	CS_RSYNC_REFRESH,
	/*
	 * Currently checking older RRDP deltas, in descending order,
	 * until (and including) Fallback's manifest number
	 */
	CS_RRDP_DELTAS,
	/* Checking the RRDP cage that succeeded in the previous cycle */
	CS_RRDP_FALLBACK,
	/* Checking the rsync cage that succeeded in the previous cycle */
	CS_RSYNC_FALLBACK,
	/* Nothing worked */
	CS_FAIL,
};

struct rpp_querier {
	enum rpp_querier_status status;

	struct rrdp_dao *rrdp;
	struct rsync_dao *rsync;

	struct extension_uris *uris;
};

#define LOCKFILE ".lock"
#define METAFILE "meta.json"
#define TAGNAME_VERSION "fort-version"

static void
delete_node(struct cache_table *tbl, struct cache_node *node, void *arg)
{
	pr_trc("Deleting node: %s", uri_str(&node->map.url));

	if (tbl)
		HASH_DEL(tbl->nodes, node);

	map_cleanup(&node->map);
	switch (node->ctx.type) {
	case CT_RRDP:
		rrdpctx_free(node->ctx.v.rrdp);
		break;
	case CT_RSYNC:
		rsync_free(node->ctx.v.rsync);
		break;
	case CT_TA:
		tactx_free(node->ctx.v.ta);
		break;
	}
	free(node);
}

static void
foreach_node(void (*cb)(struct cache_table *, struct cache_node *, void *),
    void *arg)
{
	struct cache_node *node, *tmp;

	HASH_ITER(hh, cache.rsync.nodes, node, tmp)
		cb(&cache.rsync, node, arg);
	HASH_ITER(hh, cache.https.nodes, node, tmp)
		cb(&cache.https, node, arg);
}

static void
flush_nodes(void)
{
	foreach_node(delete_node, NULL);
}

/*
 * - Result must not be cleant.
 * - strlen(uri_str(module)) should not be trusted.
 */
static bool
get_rsync_module(struct uri const *url, struct uri *module)
{
	char const *str;
	array_index u;
	unsigned int slashes;

	str = uri_str(url);
	slashes = 0;
	for (u = 0; str[u] != 0; u++)
		if (str[u] == '/') {
			slashes++;
			if (slashes == 4) {
				__uri_init(module, str, u);
				return true;
			}
		}

	if (slashes == 3 && str[u - 1] != '/') {
		*module = *url;
		return true;
	}

	pr_err("Url '%s' does not appear to have an rsync module.", str);
	return false;
}

char const *
strip_rsync_module(char const *url)
{
	array_index u;
	unsigned int slashes;

	slashes = 0;
	for (u = 0; url[u] != 0; u++)
		if (url[u] == '/') {
			slashes++;
			if (slashes == 4)
				return url + u + 1;
		}

	return NULL;
}

static json_t *
node2json(struct cache_node const *node)
{
	json_t *json;

	if (node->ctx.type == CT_RRDP && node->ctx.v.rrdp == NULL)
		/* Dl failed and there was no state; normal so silent. */
		return NULL;

	json = json_obj_new();
	if (json == NULL)
		return NULL;

	if (json_add_str(json, "uri", uri_str(&node->map.url)))
		goto fail;
	if (json_add_str(json, "path", node->map.path))
		goto fail;
	if (node->attempt_ts && json_add_ts(json, "attempt", node->attempt_ts))
		goto fail;
	if (node->success_ts && json_add_ts(json, "success", node->success_ts))
		goto fail;
	switch (node->ctx.type) {
	case CT_RRDP:
		if (json_object_add(json, "rrdp", rrdp_ctx2json(node->ctx.v.rrdp)))
			goto fail;
		break;
	case CT_RSYNC:
		if (json_object_add(json, "rsync", rsync_ctx2json(node->ctx.v.rsync)))
			goto fail;
		break;
	case CT_TA:
		break;
	default:
		pr_panic("Unknown context type: %d", node->ctx.type);
	}

	return json;

fail:	json_decref(json);
	return NULL;
}

static validation_verdict dl_rsync(struct cache_node *);
static validation_verdict dl_ta_http(struct cache_node *);
static validation_verdict dl_rrdp(struct cache_node *);

static void
init_table(struct cache_table *tbl, char *name, bool enabled)
{
	memset(tbl, 0, sizeof(*tbl));
	tbl->name = name;
	tbl->enabled = enabled;
	cseq_init(&tbl->seq, name, 0, false);
	panic_on_fail(pthread_mutex_init(&tbl->lock, NULL),
	    "pthread_mutex_init");
}

static void
init_tables(void)
{
	init_table(&cache.rsync, "rsync", config_get_rsync_enabled());
	init_table(&cache.https, "https", config_get_http_enabled());
}

static int
reset_cache_dir(void)
{
	DIR *dir;
	struct dirent *file;
	int tmperr, abserr;
	unsigned int deleted;

	pr_trc("Resetting cache...");

	abserr = 0;
	deleted = 0;

	dir = opendir(".");
	if (dir == NULL)
		goto end;

	FOREACH_DIR_FILE(dir, file)
		if (!S_ISDOTS(file) && strcmp(file->d_name, LOCKFILE) != 0) {
			tmperr = file_rm_rf(file->d_name);
			if (tmperr)
				abserr = tmperr;
			deleted++;
		}

end:	tmperr = errno;
	if (tmperr)
		abserr = tmperr;
	if (abserr)
		pr_wrn("Cannot reset cache: %s", strerror(abserr));
	else
		pr_trc(deleted > 0 ? "Cache reset." : "Cache was empty.");
	closedir(dir);
	return abserr;
}

static void
init_cachedir_tag(void)
{
	static char const *filename = "CACHEDIR.TAG";
	if (file_stat_errno(filename) == ENOENT)
		file_write_txt(filename,
		   "Signature: 8a477f597d28d172789f06886806bc55\n"
		   "# This file is a cache directory tag created by Fort.\n"
		   "# For information about cache directory tags, see:\n"
		   "#	https://bford.info/cachedir/\n");
}

static int
lock_cache(void)
{
	int fd;
	int error;

	pr_trc("touch " LOCKFILE);

	/*
	 * Suppose we get SIGTERM in the middle of this function.
	 *
	 * 1. open() then lockfile_owned = 1, we're interrupted between them:
	 *    The handler doesn't delete our lock.
	 * 2. lockfile_owned = 1 then open(), we're interrupted between them:
	 *    The handler deletes some other instance's lock.
	 *
	 * 1 is better because we already couldn't guarantee the lock was
	 * deleted on every situation. (SIGKILL)
	 */

	fd = open(LOCKFILE, O_CREAT | O_EXCL, 0644);
	if (fd < 0) {
		error = errno;
		pr_err("Cannot create lockfile '%s/" LOCKFILE "': %s",
		    config_get_local_repository(), strerror(error));
		return error;
	}
	close(fd);

	lockfile_owned = 1;
	return 0;
}

static void
unlock_cache(void)
{
	pr_trc("rm " LOCKFILE);

	if (!lockfile_owned) {
		pr_trc("The cache wasn't locked.");
		return;
	}

	if (unlink(LOCKFILE) < 0) {
		int error = errno;
		pr_err("Cannot remove lockfile: %s", strerror(error));
		if (error != ENOENT)
			return;
	}

	lockfile_owned = 0;
}

/* THIS FUNCTION CAN BE CALLED FROM A SIGNAL HANDLER. */
void
cache_atexit(void)
{
	if (lockfile_owned)
		unlink(LOCKFILE);
}

int
cache_setup1(void)
{
	char const *cachedir;
	int error;

	cachedir = config_get_local_repository();

	error = file_mkdir(cachedir, true);
	if (error)
		return error;

	pr_trc("cd %s", cachedir);
	if (chdir(cachedir) < 0) {
		error = errno;
		pr_err("Cannot cd to %s: %s", cachedir, strerror(error));
		return error;
	}

	return 0;
}

int
cache_setup2(void)
{
	int error;

	init_tables();

	errno = 0;
	error = atexit(cache_atexit);
	if (error) {
		int err2 = errno;
		pr_err("Cannot register cache's exit function.");
		pr_err("Error message attempt 1: %s", strerror(error));
		pr_err("Error message attempt 2: %s", strerror(err2));
		return error;
	}

	return 0;
}

static struct cache_node *
json2node(json_t *json)
{
	struct cache_node *node;
	char const *path;
	json_t *rrdp, *rsync;
	int error;

	node = pzalloc(sizeof(struct cache_node));

	error = json_get_uri(json, "uri", &node->map.url);
	if (error) {
		pr_trc("uri: %s", strerror(abs(error)));
		goto node;
	}

	error = json_get_str(json, "path", &path);
	if (error) {
		pr_trc("path: %s", strerror(abs(error)));
		goto url;
	}
	node->map.path = pstrdup(path);

	error = json_get_ts(json, "attempt", &node->attempt_ts);
	if (error != 0 && error != ENOENT) {
		pr_trc("attempt: %s", strerror(error));
		goto path;
	}

	error = json_get_ts(json, "success", &node->success_ts);
	if (error != 0 && error != ENOENT) {
		pr_trc("success: %s", strerror(error));
		goto path;
	}

	error = json_get_object(json, "rrdp", &rrdp);
	if (error < 0) {
		pr_trc("rrdp: %s", strerror(error));
		goto path;
	}
	if (error == 0) {
		node->ctx.type = CT_RRDP;
		if (rrdp_json2ctx(rrdp, node->map.path, &node->ctx.v.rrdp))
			goto path;
	}

	error = json_get_object(json, "rsync", &rsync);
	if (error < 0) {
		pr_trc("rsync: %s", strerror(error));
		goto path;
	}
	if (error == 0) {
		node->ctx.type = CT_RSYNC;
		if (rsync_json2ctx(rsync, &node->map, &node->ctx.v.rsync))
			goto path;
	}

	if (node->ctx.type == 0) {
		node->ctx.type = CT_TA;
		node->ctx.v.ta = tactx_create(path);
	}

	return node;

path:	free(node->map.path);
url:	uri_cleanup(&node->map.url);
node:	free(node);
	return NULL;
}

static int
check_root_metafile(void)
{
	json_error_t jerr;
	json_t *root;
	char const *file_version;
	int error;

	pr_trc("Loading " METAFILE "...");

	root = json_load_file(METAFILE, 0, &jerr);
	if (root == NULL) {
		if (json_error_code(&jerr) == json_error_cannot_open_file) {
			pr_trc(METAFILE " does not exist.");
			return ENOENT;
		} else {
			pr_err("Json parsing failure at %s (%d:%d): %s",
			    METAFILE, jerr.line, jerr.column, jerr.text);
			return EINVAL;
		}
	}

	if (json_typeof(root) != JSON_OBJECT) {
		pr_err("The root tag of " METAFILE " is not an object.");
		goto fail;
	}

	error = json_get_str(root, TAGNAME_VERSION, &file_version);
	if (error) {
		if (error > 0)
			pr_err(METAFILE " is missing the '"
			    TAGNAME_VERSION "' tag.");
		goto fail;
	}
	if (strcmp(file_version, PACKAGE_VERSION) != 0) {
		pr_err("The cache was written by Fort %s; "
		    "I need to clear it.", file_version);
		goto fail;
	}

	json_decref(root);
	pr_trc(METAFILE " loaded.");
	return 0;

fail:	json_decref(root);
	return EINVAL;
}

static void
collect_meta(struct cache_table *tbl, struct dirent *dir)
{
	char filename[64];
	int wrt;
	json_error_t jerr;
	json_t *root;
	struct cache_node *node;

	if (S_ISDOTS(dir))
		return;

	pr_trc("Collecting metadata: %s/%s.json", tbl->name, dir->d_name);

	wrt = snprintf(filename, 64, "%s/%s.json", tbl->name, dir->d_name);
	if (wrt >= 64)
		pr_panic("collect_meta: %d %s %s", wrt, tbl->name, dir->d_name);

	pr_clutter("%s: Loading...", filename);

	root = json_load_file(filename, 0, &jerr);
	if (root == NULL) {
		if (json_error_code(&jerr) == json_error_cannot_open_file)
			pr_wrn("%s: File does not exist.", filename);
		else
			pr_wrn("%s: Json parsing failure at (%d:%d): %s",
			    filename, jerr.line, jerr.column, jerr.text);
		return;
	}

	if (json_typeof(root) != JSON_OBJECT) {
		pr_wrn("%s: Root tag is not an object.", filename);
		goto end;
	}

	node = json2node(root);
	if (node != NULL) {
		// XXX worry about dupes
		HASH_ADD_KEYPTR(hh, tbl->nodes,
		    uri_str(&node->map.url), uri_len(&node->map.url),
		    node);
	} else {
		pr_wrn("Malformed JSON!");
	}

	pr_clutter("%s: Loaded.", filename);
end:	json_decref(root);
}

static void
collect_metas(struct cache_table *tbl)
{
	DIR *dir;
	struct dirent *file;
	unsigned long id, max_id;
	int error;

	dir = opendir(tbl->name);
	if (dir == NULL) {
		error = errno;
		if (error != ENOENT)
			pr_wrn("Cannot open %s: %s",
			    tbl->name, strerror(error));
		return;
	}

	max_id = 0;
	FOREACH_DIR_FILE(dir, file) {
		if (hex2ulong(file->d_name, &id) != 0)
			continue;
		if (id > max_id)
			max_id = id;
		collect_meta(tbl, file);
	}
	error = errno;
	if (error)
		pr_wrn("Could not finish traversing %s: %s",
		    tbl->name, strerror(error));

	closedir(dir);

	tbl->seq.pfx.str = tbl->name;
	tbl->seq.pfx.len = strlen(tbl->name);
	tbl->seq.next_id = max_id + 1;
	tbl->seq.pathlen = tbl->seq.pfx.len;
	tbl->seq.free_prefix = false;
}

static int
load_index(void)
{
	int error;

	error = check_root_metafile();
	if (error)
		return error;

	collect_metas(&cache.rsync);
	collect_metas(&cache.https);
	return 0;
}

int
cache_prepare(void)
{
	int error;

	error = lock_cache();
	if (error)
		return error;

	if (load_index() != 0) {
		error = reset_cache_dir();
		if (error)
			goto fail;
	}

	error = file_mkdir("rsync", true);
	if (error)
		goto fail;
	error = file_mkdir("https", true);
	if (error)
		goto fail;
	error = file_mkdir(CACHE_TMPDIR, true);
	if (error)
		goto fail;
	init_cachedir_tag();

	return 0;

fail:	flush_nodes();
	unlock_cache();
	return error;
}

static validation_verdict
dl_rsync(struct cache_node *module)
{
	int error;
	error = rsync_queue(&module->map.url, module->map.path, false);
	return error ? VV_FAIL : VV_BUSY;
}

static validation_verdict
dl_ta_rsync(struct cache_node *file)
{
	char tmppath[CACHE_TMPFILE_BUFLEN];

	cache_tmpfile(tmppath);

	if (!file->ctx.v.ta)
		file->ctx.v.ta = tactx_create(NULL);
	tactx_set_refresh(file->ctx.v.ta, tmppath);

	return rsync_queue(&file->map.url, tmppath, true) ? VV_FAIL : VV_BUSY;
}

static validation_verdict
dl_rrdp(struct cache_node *notif)
{
	bool changed;

	if (rrdp_update(&notif->map.url, notif->map.path, notif->success_ts,
			&changed, &notif->ctx.v.rrdp))
		return VV_FAIL;
	if (changed)
		notif->success_ts = notif->attempt_ts;
	return VV_CONTINUE;
}

static validation_verdict
dl_ta_http(struct cache_node *file)
{
	char tmppath[CACHE_TMPFILE_BUFLEN];
	bool changed;

	cache_tmpfile(tmppath);

	if (http_download(&file->map.url, tmppath, file->success_ts, &changed))
		return VV_FAIL;

	if (!file->ctx.v.ta)
		file->ctx.v.ta = tactx_create(NULL);

	if (changed) {
		file->success_ts = file->attempt_ts;
		tactx_set_refresh(file->ctx.v.ta, tmppath);
	} else {
		tactx_set_unchanged(file->ctx.v.ta);
	}

	return VV_CONTINUE;
}

/* Caller must lock @tbl->lock */
static struct cache_node *
find_node(struct cache_table *tbl, struct uri const *url)
{
	struct cache_node *node;
	HASH_FIND(hh, tbl->nodes, uri_str(url), uri_len(url), node);
	return node;
}

static struct cache_node *
provide_node(struct cache_table *tbl, struct uri const *url,
    enum context_type ctx_type)
{
	struct cache_node *node;

	node = find_node(tbl, url);
	if (node)
		return (node->ctx.type == ctx_type) ? node : NULL;

	node = pzalloc(sizeof(struct cache_node));
	uri_copy(&node->map.url, url);
	node->map.path = cseq_next(&tbl->seq, NULL);
	if (!node->map.path) {
		uri_cleanup(&node->map.url);
		free(node);
		return NULL;
	}
	node->ctx.type = ctx_type;

	url = &node->map.url;
	HASH_ADD_KEYPTR(hh, tbl->nodes, uri_str(url), uri_len(url), node);
	return node;
}

static void
rm_metadata(struct cache_node *node)
{
	char *filename;
	int error;

	filename = str_concat(node->map.path, ".json");
	pr_trc("rm -f %s", filename);
	if (unlink(filename) < 0) {
		error = errno;
		if (error == ENOENT)
			pr_clutter("%s already doesn't exist.", filename);
		else
			pr_wrn("Cannot rm %s: %s", filename, strerror(errno));
	}

	free(filename);
}

static void
write_metadata(struct cache_node *node)
{
	char *filename;
	json_t *json;

	json = node2json(node);
	if (!json)
		return;
	filename = str_concat(node->map.path, ".json");

	pr_trc("echo \"$json\" > %s", filename);
	if (json_dump_file(json, filename, JSON_INDENT(2)))
		pr_err("Unable to write %s; unknown cause.", filename);

	free(filename);
	json_decref(json);
}

/*
 * During DLS_ONGOING, the rsync subprocess downloaded the files.
 * However, because it had to do an execvp(), the subprocess was unable to
 * update the cache metadata.
 * So that work had to be deferred to the first thread that grabs the task as a
 * DLS_ONGOING2.
 * This is that function.
 */
static validation_verdict
rsync_post_process(struct cache_node *node)
{
	switch (node->ctx.type) {
	case CT_RSYNC:
		if (rsync_reindex(&node->ctx.v.rsync, &node->map) != 0)
			return VV_FAIL;
		rsync_print(node->ctx.v.rsync, 0);
		return VV_CONTINUE;
	case CT_TA:
		tactx_print(node->ctx.v.ta, 0);
		return VV_CONTINUE;

	case CT_RRDP:
		break;
	}


	return VV_FAIL;
}

/*
 * Check @result even on VV_FAIL; even if refresh failed, you might still get a
 * fallback.
 * By contract, @result->state will be DLS_FRESH on return VV_CONTINUE.
 *
 * @result belongs to the database; don't free it.
 */
static validation_verdict
do_refresh(struct cache_table *tbl, struct uri const *uri, bool single,
    dl_cb dl, struct cache_node **result)
{
	struct uri module;
	struct cache_node *node;
	bool downloaded = false;

	pr_trc("Trying %s (online)...", uri_str(uri));
	*result = NULL;

	if (!tbl->enabled) {
		pr_trc("Protocol disabled.");
		return VV_FAIL;
	}

	if (tbl == &cache.rsync) {
		if (single)
			module = *uri;
		else if (!get_rsync_module(uri, &module))
			return VV_FAIL;
		mutex_lock(&tbl->lock);
		node = provide_node(tbl, &module, single ? CT_TA : CT_RSYNC);
	} else {
		mutex_lock(&tbl->lock);
		node = provide_node(tbl, uri, single ? CT_TA : CT_RRDP);
	}
	if (!node) {
		mutex_unlock(&tbl->lock);
		return VV_FAIL;
	}

	/*
	 * Reminder: If the state is ONGOING, DO NOT read anything other than
	 * the lock and state.
	 */

	switch (node->state) {
	case DLS_OUTDATED:
		node->state = DLS_ONGOING;
		mutex_unlock(&tbl->lock);

		node->attempt_ts = time_fatal();
		rm_metadata(node);
		node->verdict = dl(node);
		if (node->verdict == VV_BUSY)
			goto ongoing;
		write_metadata(node);
		downloaded = true;

		mutex_lock(&tbl->lock);
		node->state = DLS_FRESH;
		break;
	case DLS_ONGOING:
ongoing:	mutex_unlock(&tbl->lock);
		pr_trc("Refresh ongoing.");
		return VV_BUSY;
	case DLS_ONGOING2:
		node->state = DLS_ONGOING; /* Shoo other threads for now */
		mutex_unlock(&tbl->lock);

		node->verdict = rsync_post_process(node);
		downloaded = true;

		mutex_lock(&tbl->lock);
		node->state = DLS_FRESH;
		break;
	case DLS_FRESH:
		pr_trc("Already downloaded.");
		break;
	default:
		pr_panic("Unknown node state: %d", node->state);
	}

	mutex_unlock(&tbl->lock);
	/* node->state is guaranteed to be DLS_FRESH at this point. */

	*result = node;

	if (downloaded) /* Kickstart tasks that fell into DLS_ONGOING */
		task_wakeup_dormants();

	if (node->verdict == VV_FAIL) {
		pr_trc("Refresh failed.");
		return VV_FAIL;
	}

	pr_trc("Refresh succeeded.");
	return VV_CONTINUE;
}

/* XXX Fallback only if parent is fallback */
/* XXX Make sure somewhere validates rpkiManifest matches caRepository */

validation_verdict
querier_downgrade(struct rpp_querier *dao)
{
	struct cache_node *node;
	validation_verdict vv;

	switch (dao->status) {
	case CS_START:
		if (uri_str(&dao->uris->rpkiNotify) != NULL) {
			vv = do_refresh(&cache.https, &dao->uris->rpkiNotify,
			    false, dl_rrdp, &node);
			if (node != NULL) {
				dao->status = CS_RRDP_REFRESH;
				dao->rrdp = rrdpdao_create(node->ctx.v.rrdp,
				   &dao->uris->caRepository);
			}
			if (vv == VV_CONTINUE) {
				pr_trc("Validating RRDP Refresh.");
				return VV_CONTINUE;
			}
			if (vv == VV_BUSY)
				return VV_BUSY;
		}
		/* No break */

	case CS_RRDP_REFRESH:
		vv = do_refresh(&cache.rsync, &dao->uris->caRepository,
		    false, dl_rsync, &node);
		if (vv == VV_CONTINUE) {
			pr_trc("Validating rsync refresh.");
			dao->status = CS_RSYNC_REFRESH;
			dao->rsync = rsyncdao_create(node->ctx.v.rsync,
			    &dao->uris->caRepository);
			return VV_CONTINUE;
		}
		if (vv == VV_BUSY)
			return VV_BUSY;
		/* No break */

	case CS_RSYNC_REFRESH:
	case CS_RRDP_DELTAS:
		if (rrdpdao_downgrade_delta(dao->rrdp)) {
			pr_trc("Validating RRDP deltas.");
			dao->status = CS_RRDP_DELTAS;
			return VV_CONTINUE;
		}
		/* No break */

	case CS_RRDP_FALLBACK:
		if (rrdpdao_downgrade_fb(dao->rrdp)) {
			pr_trc("Validating RRDP fallback.");
			dao->status = CS_RRDP_FALLBACK;
			return VV_CONTINUE;
		}
		/* No break */

	case CS_RSYNC_FALLBACK:
		if (rsyncdao_downgrade(dao->rsync)) {
			pr_trc("Validating rsync fallback.");
			dao->status = CS_RSYNC_FALLBACK;
			return VV_CONTINUE;
		}
		/* No break */

	case CS_FAIL:
		dao->status = CS_FAIL;
		break;
	}

	return VV_FAIL;
}

struct rpp_querier *
querier_create(struct extension_uris *uris)
{
	struct rpp_querier *querier;

	querier = pzalloc(sizeof(struct rpp_querier));
	querier->status = CS_START;
	querier->uris = uris;

	return querier;
}

void
querier_free(struct rpp_querier *querier)
{
	if (querier) {
		rrdpdao_free(querier->rrdp);
		rsyncdao_free(querier->rsync);
		free(querier);
	}
}

/* Result needs free() */
struct cache_file *
querier_map(struct rpp_querier *querier, struct uri const *url)
{
	switch (querier->status) {
	case CS_RRDP_REFRESH:
	case CS_RRDP_DELTAS:
	case CS_RRDP_FALLBACK:
		return rrdpdao_map(querier->rrdp, url);

	case CS_RSYNC_REFRESH:
	case CS_RSYNC_FALLBACK:
		return rsyncdao_map(querier->rsync, url);

	case CS_START:
	case CS_FAIL:
		break;
	}

	return NULL;
}

void
querier_get_fallback_mftnums(struct rpp_querier *querier,
    struct mft_meta const **rrdp, struct mft_meta const **rsync)
{
	*rrdp = rrdpdao_fallback_mftnum(querier->rrdp);
	*rsync = rsyncdao_fallback_mftnum(querier->rsync);
}

void
cache_commit_rpp(struct rpp_querier *querier, struct rpp *rpp)
{
	switch (querier->status) {
	case CS_RRDP_REFRESH:
	case CS_RRDP_DELTAS:
	case CS_RRDP_FALLBACK:
		rrdpdao_commit(querier->rrdp, rpp);
		break;

	case CS_RSYNC_REFRESH:
	case CS_RSYNC_FALLBACK:
		rsyncdao_commit(querier->rsync, rpp);
		break;

	case CS_START:
	case CS_FAIL:
		break;
	}
}

void
rsync_finished(struct uri const *url, char const *path)
{
	struct cache_node *node;

	mutex_lock(&cache.rsync.lock);

	node = find_node(&cache.rsync, url);
	if (node == NULL) {
		mutex_unlock(&cache.rsync.lock);
		pr_err("rsync '%s -> %s' finished, but cache node does not exist.",
		    uri_str(url), path);
		return;
	}
	if (node->state != DLS_ONGOING)
		pr_wrn("rsync '%s -> %s' finished, but existing node was not in ONGOING state.",
		    uri_str(url), path);

	node->state = DLS_ONGOING2;
	node->verdict = VV_CONTINUE;
	node->success_ts = node->attempt_ts;
	mutex_unlock(&cache.rsync.lock);

	task_wakeup_dormants();
}

static void
cachent_print(struct cache_node *node, int indent)
{
	if (!node)
		return;

	printf("%*s", indent, "");
	switch (node->ctx.type) {
	case CT_RRDP:
		printf("[RRDP Node] ");
		break;
	case CT_RSYNC:
		printf("[rsync Node] ");
		break;
	case CT_TA:
		printf("[TA Node] ");
		break;
	}

	printf("uri:%s path:%s ", uri_str(&node->map.url), node->map.path);
	switch (node->state) {
	case DLS_OUTDATED:
		printf("state:stale ");
		break;
	case DLS_ONGOING:
		printf("state:downloading ");
		break;
	case DLS_ONGOING2:
		printf("state:post-processing ");
		break;
	case DLS_FRESH:
		printf("state:fresh(%s) ", node->verdict);
		break;
	}

	printf("attempt:%lx success:%lx\n", node->attempt_ts, node->success_ts);
	switch (node->ctx.type) {
	case CT_RRDP:
		rrdpctx_print(node->ctx.v.rrdp, indent + 2);
		break;
	case CT_RSYNC:
		rsync_print(node->ctx.v.rsync, indent + 2);
		break;
	case CT_TA:
		tactx_print(node->ctx.v.ta, indent + 2);
		break;
	}
}

static void
table_print(struct cache_table *tbl)
{
	struct cache_node *node, *tmp;

	printf("[%s Table] enabled:%d seq:%s/%lx\n",
	    tbl->name, tbl->enabled,
	    tbl->seq.pfx.str, tbl->seq.next_id);
	HASH_ITER(hh, tbl->nodes, node, tmp)
		cachent_print(node, 2);
}

void
cache_print(void)
{
	table_print(&cache.rsync);
	table_print(&cache.https);
}

static void
cleanup_node(struct cache_table *tbl, struct cache_node *node, void *arg)
{
	bool salvage;

	pr_trc("Cleaning up node: %s", node->map.path);

	rm_metadata(node);

	salvage = false;
	switch (node->ctx.type) {
	case CT_RRDP:
		salvage = rrdpctx_cleanup(node->ctx.v.rrdp);
		break;
	case CT_RSYNC:
		salvage = rsync_cleanup(node->ctx.v.rsync);
		break;
	case CT_TA:
		salvage = tactx_cleanup(node->ctx.v.ta, node->map.path);
		break;
	}

	if (salvage) {
		pr_trc("Preserving node.");
		write_metadata(node);
	} else {
		pr_trc("Deleting node.");
		file_rm_rf(node->map.path);
		delete_node(tbl, node, NULL);
	}
}

/* Deletes obsolete files and nodes from the cache. */
static void
cleanup_cache(void)
{
	pr_trc("Deleting abandoned files...");
	foreach_node(cleanup_node, NULL);
	pr_trc("Abandoned files deleted.");

	pr_trc("Deleting tmp/...");
	file_rm_rf(CACHE_TMPDIR);
	pr_trc("tmp/ deleted.");

	// XXX delete nodes which lack cages
	// XXX delete cages that lack nodes
	// XXX delete nodes that lack indexes
	// etc
}

void
cache_commit(void)
{
	pr_trc("============ Committing cache ============");
	cache_print();
	cleanup_cache();
	file_write_txt(METAFILE, "{ \"fort-version\": \"" PACKAGE_VERSION "\" }");
	unlock_cache();
	flush_nodes();
}

void
exturis_init(struct extension_uris *uris)
{
	memset(uris, 0, sizeof(*uris));
}

void
exturis_cleanup(struct extension_uris *uris)
{
	uri_cleanup(&uris->caRepository);
	uri_cleanup(&uris->rpkiNotify);
	uri_cleanup(&uris->rpkiManifest);
	uri_cleanup(&uris->crldp);
	uri_cleanup(&uris->caIssuers);
	uri_cleanup(&uris->signedObject);
}

static validation_verdict
fquery_create_refresh(struct cache_table *tbl, dl_cb dl, struct uri const *url,
    struct file_querier **_result)
{
	struct file_querier *result;
	struct cache_node *node;
	validation_verdict vv;

	vv = do_refresh(tbl, url, true, dl, &node);
	if (vv != VV_CONTINUE)
		return vv;
	if (node->ctx.type != CT_TA)
		return VV_FAIL;

	result = pmalloc(sizeof(struct file_querier));
	result->node = node;
	result->is_refresh = true;

	*_result = result;
	return VV_CONTINUE;
}

validation_verdict
fquery_refresh_https(struct uri const *url, struct file_querier **result)
{
	return fquery_create_refresh(&cache.https, dl_ta_http, url, result);
}

validation_verdict
fquery_refresh_rsync(struct uri const *url, struct file_querier **result)
{
	return fquery_create_refresh(&cache.rsync, dl_ta_rsync, url, result);
}

static validation_verdict
fquery_create_fallback(struct cache_table *tbl, struct uri const *url,
    struct file_querier **_result)
{
	struct file_querier *result;
	struct cache_node *node;

	node = provide_node(tbl, url, CT_TA);
	if (!node || !node->ctx.v.ta)
		return VV_FAIL;

	result = pmalloc(sizeof(struct file_querier));
	result->node = node;
	result->is_refresh = false;

	*_result = result;
	return VV_CONTINUE;
}

validation_verdict
fquery_fallback_https(struct uri const *url, struct file_querier **result)
{
	return fquery_create_fallback(&cache.https, url, result);
}

validation_verdict
fquery_fallback_rsync(struct uri const *url, struct file_querier **result)
{
	return fquery_create_fallback(&cache.rsync, url, result);
}

char const *
fquerier_map(struct file_querier *querier)
{
	return tactx_map(querier->node->ctx.v.ta, querier->is_refresh);
}

void
fquerier_commit(struct file_querier *querier)
{
	tactx_preserve(querier->node->ctx.v.ta, querier->is_refresh);
}
