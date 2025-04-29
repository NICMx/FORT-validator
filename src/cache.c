#include "cache.h"

#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc.h"
#include "cachetmp.h"
#include "common.h"
#include "config.h"
#include "configure_ac.h"
#include "file.h"
#include "http.h"
#include "json_util.h"
#include "log.h"
#include "rrdp.h"
#include "rsync.h"
#include "task.h"
#include "types/array.h"
#include "types/path.h"
#include "types/str.h"
#include "types/url.h"
#include "types/uthash.h"

enum node_state {
	/* Refresh nodes: Not downloaded yet (stale) */
	/* Fallback nodes: Queued for commit */
	DLS_OUTDATED = 0,
	/* Refresh nodes: Download in progress */
	/* Fallback nodes: N/A */
	DLS_ONGOING,
	/* Refresh nodes: Download complete */
	/* Fallback nodes: Committed */
	DLS_FRESH,
};

struct node_key {
	/*
	 * Hash table indexer.
	 *
	 * If this is an rsync node, @id is the caRepository.
	 * If this is an HTTP node, @id is the simple URL.
	 * If this is an RRDP refresh node, @id is the rpkiNotify.
	 * If this is an RRDP fallback node, @id is `rpkiNotify\0caRepository`.
	 */
	char *id;
	size_t idlen;

	/*
	 * If node is rsync, @http is NULL.
	 * If node is HTTP, @http is the simple URL.
	 * If node is RRDP, @http is the rpkiNotify.
	 *
	 * Points to @id; do not clean.
	 */
	struct uri http;
	/*
	 * If node is rsync, @rsync is the simple URL.
	 * If node is HTTP, @rsync is NULL.
	 * If node is RRDP, @rsync is the caRepository.
	 *
	 * Points to @id; do not clean.
	 */
	struct uri rsync;
};

/*
 * This is a delicate structure; pay attention.
 *
 * During the multithreaded stage of the validation cycle, one thread will
 * switch @state from DLS_OUTDATED to DLS_ONGOING, and become the only writer
 * for the given node. Other threads are only allowed to lock, and with the
 * lock, read @state (to find out they shouldn't touch anything else).
 *
 * The entire cache_node (except @hh) becomes (effectively) constant when the
 * writer thread upgrades @state to DLS_FRESH.
 *
 * This is intended to allow the cache (ie. this module) to pass the node to the
 * validation code (through cache_cage) without having to allocate a deep copy
 * (@rrdp can be somewhat large), and to allow the validation code to read-only
 * the node (except @hh) without having to hold the table mutex.
 *
 * C cannot entirely ensure the node remains constant after it's handed outside;
 * this must be done through careful coding and review.
 */
struct cache_node {
	struct node_key key;
	char *path;

	enum node_state state;
	/* Result code of recent dl attempt (DLS_FRESH only) */
	int dlerr;
	time_t attempt_ts;	/* Refresh: Dl attempt. Fallback: Unused */
	time_t success_ts;	/* Refresh: Dl success. Fallback: Commit */

	struct mft_meta mft;	/* RPP fallbacks only */
	struct rrdp_state *rrdp;

	UT_hash_handle hh;	/* Hash table hook */
};

typedef int (*dl_cb)(struct cache_node *rpp);

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
	dl_cb download;
	pthread_mutex_t lock;
};

static struct rpki_cache {
	/* Latest view of the remote rsync modules */
	/* rsync modules (repositories); indexed by plain rsync URL */
	struct cache_table rsync;
	/* Latest view of the remote HTTPS TAs */
	/* HTTPS files; indexed by plain HTTPS URL */
	struct cache_table https;
	/* Latest view of the remote RRDP cages */
	/* RRDP modules (repositories); indexed by rpkiNotify */
	struct cache_table rrdp;

	/* Committed (offline fallback hard links) RPPs and TAs */
	/* RPPs indexed by [rpkiNotif] + caRepo; TAs indexed by plain URL. */
	struct cache_table fallback;
} cache;

/* "Is the lockfile ours?" */
static volatile sig_atomic_t lockfile_owned;

struct cache_cage {
	struct cache_node const *refresh;
	struct cache_node const *fallback;
	struct uri rpkiNotify;
	struct mft_meta *mft;		/* Fallback */
};

struct cache_commit {
	struct uri rpkiNotify;
	struct uri caRepository;
	struct cache_mapping *files;
	size_t nfiles;
	struct mft_meta mft;		/* RPPs commits only */
	STAILQ_ENTRY(cache_commit) lh;
};

static STAILQ_HEAD(cache_commits, cache_commit) commits = STAILQ_HEAD_INITIALIZER(commits);
static pthread_mutex_t commits_lock = PTHREAD_MUTEX_INITIALIZER;

#define LOCKFILE ".lock"
#define METAFILE "meta.json"
#define TAGNAME_VERSION "fort-version"

#ifdef UNIT_TESTING
static void __delete_node_cb(struct cache_node const *);
#endif

static void
delete_node(struct cache_table *tbl, struct cache_node *node, void *arg)
{
#ifdef UNIT_TESTING
	__delete_node_cb(node);
#endif

	if (tbl)
		HASH_DEL(tbl->nodes, node);

	free(node->key.id);
	free(node->path);
	rrdp_state_free(node->rrdp);
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
	HASH_ITER(hh, cache.rrdp.nodes, node, tmp)
		cb(&cache.rrdp, node, arg);
	HASH_ITER(hh, cache.fallback.nodes, node, tmp)
		cb(&cache.fallback, node, arg);
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

	pr_val_err("Url '%s' does not appear to have an rsync module.", str);
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
node2json(struct cache_node *node)
{
	char const *str;
	json_t *json;

	json = json_obj_new();
	if (json == NULL)
		return NULL;

	str = uri_str(&node->key.http);
	if (str && json_add_str(json, "http", str))
		goto fail;
	str = uri_str(&node->key.rsync);
	if (str && json_add_str(json, "rsync", str))
		goto fail;
	if (json_add_str(json, "path", node->path))
		goto fail;
	if (node->dlerr && json_add_int(json, "error", node->dlerr))
		goto fail;
	if (node->attempt_ts && json_add_ts(json, "attempt", node->attempt_ts))
		goto fail;
	if (node->success_ts && json_add_ts(json, "success", node->success_ts))
		goto fail;
	if (node->mft.num.size && json_add_bigint(json, "mftNum", &node->mft.num))
		goto fail;
	if (node->mft.update && json_add_ts(json, "mftUpdate", node->mft.update))
		goto fail;
	if (node->rrdp)
		if (json_object_add(json, "rrdp", rrdp_state2json(node->rrdp)))
			goto fail;

	return json;

fail:	json_decref(json);
	return NULL;
}

static int dl_rsync(struct cache_node *);
static int dl_http(struct cache_node *);
static int dl_rrdp(struct cache_node *);

static void
init_table(struct cache_table *tbl, char *name, bool enabled, dl_cb dl)
{
	memset(tbl, 0, sizeof(*tbl));
	tbl->name = name;
	tbl->enabled = enabled;
	cseq_init(&tbl->seq, name, 0, false);
	tbl->download = dl;
	panic_on_fail(pthread_mutex_init(&tbl->lock, NULL),
	    "pthread_mutex_init");
}

static void
init_tables(void)
{
	init_table(&cache.rsync, "rsync", config_get_rsync_enabled(), dl_rsync);
	init_table(&cache.https, "https", config_get_http_enabled(), dl_http);
	init_table(&cache.rrdp, "rrdp", config_get_http_enabled(), dl_rrdp);
	init_table(&cache.fallback, "fallback", true, NULL);
}

static int
reset_cache_dir(void)
{
	DIR *dir;
	struct dirent *file;
	int error;
	unsigned int deleted;

	pr_op_debug("Resetting cache...");

	dir = opendir(".");
	if (dir == NULL)
		goto fail;

	deleted = 0;
	FOREACH_DIR_FILE(dir, file)
		if (!S_ISDOTS(file) && strcmp(file->d_name, LOCKFILE) != 0) {
			error = file_rm_rf(file->d_name);
			if (error)
				goto end;
			deleted++;
		}
	if (errno)
		goto fail;

	pr_op_debug(deleted > 0 ? "Cache cleared." : "Cache was empty.");
	error = 0;
	goto end;

fail:	error = errno;
	pr_op_err("Cannot traverse the cache: %s", strerror(error));
end:	closedir(dir);
	return error;
}

static void
init_cachedir_tag(void)
{
	static char const *filename = "CACHEDIR.TAG";
	if (file_exists(filename) == ENOENT)
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

	pr_op_debug("touch " LOCKFILE);

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
		pr_op_err("Cannot create lockfile '%s/" LOCKFILE "': %s",
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
	pr_op_debug("rm " LOCKFILE);

	if (!lockfile_owned) {
		pr_op_debug("The cache wasn't locked.");
		return;
	}

	if (unlink(LOCKFILE) < 0) {
		int error = errno;
		pr_op_err("Cannot remove lockfile: %s", strerror(error));
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
cache_setup(void)
{
	char const *cachedir;
	int error;

	cachedir = config_get_local_repository();

	error = file_mkdir(cachedir, true);
	if (error)
		return error;

	pr_op_debug("cd %s", cachedir);
	if (chdir(cachedir) < 0) {
		error = errno;
		pr_op_err("Cannot cd to %s: %s", cachedir, strerror(error));
		return error;
	}

	init_tables();

	errno = 0;
	error = atexit(cache_atexit);
	if (error) {
		int err2 = errno;
		pr_op_err("Cannot register cache's exit function.");
		pr_op_err("Error message attempt 1: %s", strerror(error));
		pr_op_err("Error message attempt 2: %s", strerror(err2));
		return error;
	}

	return 0;
}

static void
init_rrdp_fallback_key(struct node_key *key, struct uri const *http,
    struct uri const *rsync)
{
	size_t hlen, rlen;

	hlen = uri_len(http);
	rlen = uri_len(rsync);

	key->idlen = hlen + rlen + 1;
	key->id = pmalloc(key->idlen + 1);
	__uri_init(&key->http, key->id, hlen);
	__uri_init(&key->rsync, key->id + hlen + 1, rlen);

	memcpy(key->id, uri_str(http), hlen + 1);
	memcpy(key->id + hlen + 1, uri_str(rsync), rlen + 1);
}

static int
init_node_key(struct node_key *key, struct uri const *http,
    struct uri const *rsync)
{
	if (http && (uri_str(http) == NULL))
		http = NULL;
	if (rsync && (uri_str(rsync) == NULL))
		rsync = NULL;

	if (http != NULL && rsync != NULL) {
		init_rrdp_fallback_key(key, http, rsync);

	} else if (rsync != NULL) {
		key->idlen = uri_len(rsync);
		key->id = pstrndup(uri_str(rsync), key->idlen);
		memset(&key->http, 0, sizeof(key->http));
		__uri_init(&key->rsync, key->id, key->idlen);

	} else if (http != NULL) {
		key->idlen = uri_len(http);
		key->id = pstrndup(uri_str(http), key->idlen);
		__uri_init(&key->http, key->id, key->idlen);
		memset(&key->rsync, 0, sizeof(key->rsync));

	} else {
		return false;
	}

	return true;
}

static struct cache_node *
json2node(json_t *json)
{
	struct cache_node *node;
	struct uri http;
	struct uri rsync;
	char const *path;
	json_t *rrdp;
	int error;

	error = json_get_uri(json, "http", &http);
	if (error && (error != ENOENT)) {
		pr_op_debug("http: %s", strerror(error));
		return NULL;
	}

	error = json_get_uri(json, "rsync", &rsync);
	if (error && (error != ENOENT)) {
		pr_op_debug("rsync: %s", strerror(error));
		uri_cleanup(&http);
		return NULL;
	}

	node = pzalloc(sizeof(struct cache_node));

	if (!init_node_key(&node->key, &http, &rsync)) {
		pr_op_debug("JSON node is missing both http and rsync tags.");
		uri_cleanup(&rsync);
		uri_cleanup(&http);
		goto nde;
	}

	uri_cleanup(&http);
	uri_cleanup(&rsync);

	error = json_get_str(json, "path", &path);
	if (error) {
		pr_op_debug("path: %s", strerror(error));
		goto key;
	}
	node->path = pstrdup(path);

	error = json_get_ts(json, "attempt", &node->attempt_ts);
	if (error != 0 && error != ENOENT) {
		pr_op_debug("attempt: %s", strerror(error));
		goto pth;
	}

	error = json_get_ts(json, "success", &node->success_ts);
	if (error != 0 && error != ENOENT) {
		pr_op_debug("success: %s", strerror(error));
		goto pth;
	}

	error = json_get_bigint(json, "mftNum", &node->mft.num);
	if (error < 0) {
		pr_op_debug("mftNum: %s", strerror(error));
		goto pth;
	}

	error = json_get_ts(json, "mftUpdate", &node->mft.update);
	if (error < 0) {
		pr_op_debug("mftUpdate: %s", strerror(error));
		goto mft;
	}

	error = json_get_object(json, "rrdp", &rrdp);
	if (error < 0) {
		pr_op_debug("rrdp: %s", strerror(error));
		goto mft;
	}
	if (error == 0 && rrdp_json2state(rrdp, node->path, &node->rrdp))
		goto mft;

	return node;

mft:	INTEGER_cleanup(&node->mft.num);
pth:	free(node->path);
key:	free(node->key.id);
nde:	free(node);
	return NULL;
}

static int
check_root_metafile(void)
{
	json_error_t jerr;
	json_t *root;
	char const *file_version;
	int error;

	pr_op_debug("Loading " METAFILE "...");

	root = json_load_file(METAFILE, 0, &jerr);
	if (root == NULL) {
		if (json_error_code(&jerr) == json_error_cannot_open_file) {
			pr_op_debug(METAFILE " does not exist.");
			return ENOENT;
		} else {
			pr_op_err("Json parsing failure at %s (%d:%d): %s",
			    METAFILE, jerr.line, jerr.column, jerr.text);
			return EINVAL;
		}
	}

	if (json_typeof(root) != JSON_OBJECT) {
		pr_op_err("The root tag of " METAFILE " is not an object.");
		goto fail;
	}

	error = json_get_str(root, TAGNAME_VERSION, &file_version);
	if (error) {
		if (error > 0)
			pr_op_err(METAFILE " is missing the '"
			    TAGNAME_VERSION "' tag.");
		goto fail;
	}
	if (strcmp(file_version, PACKAGE_VERSION) != 0) {
		pr_op_err("The cache was written by Fort %s; "
		    "I need to clear it.", file_version);
		goto fail;
	}

	json_decref(root);
	pr_op_debug(METAFILE " loaded.");
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

	wrt = snprintf(filename, 64, "%s/%s.json", tbl->name, dir->d_name);
	if (wrt >= 64)
		pr_crit("collect_meta: %d %s %s", wrt, tbl->name, dir->d_name);

	pr_clutter("%s: Loading...", filename);

	root = json_load_file(filename, 0, &jerr);
	if (root == NULL) {
		if (json_error_code(&jerr) == json_error_cannot_open_file)
			pr_op_warn("%s: File does not exist.", filename);
		else
			pr_op_warn("%s: Json parsing failure at (%d:%d): %s",
			    filename, jerr.line, jerr.column, jerr.text);
		return;
	}

	if (json_typeof(root) != JSON_OBJECT) {
		pr_op_warn("%s: Root tag is not an object.", filename);
		goto end;
	}

	node = json2node(root);
	if (node != NULL) {
		// XXX worry about dupes
		HASH_ADD_KEYPTR(hh, tbl->nodes, node->key.id, node->key.idlen,
		    node);
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
			pr_op_warn("Cannot open %s: %s",
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
		pr_op_warn("Could not finish traversing %s: %s",
		    tbl->name, strerror(error));

	closedir(dir);

	tbl->seq.prefix = tbl->name;
	tbl->seq.next_id = max_id + 1;
	tbl->seq.pathlen = strlen(tbl->name);
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
	collect_metas(&cache.rrdp);
	collect_metas(&cache.fallback);
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
	error = file_mkdir("rrdp", true);
	if (error)
		goto fail;
	error = file_mkdir("fallback", true);
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

static int
dl_rsync(struct cache_node *module)
{
	int error;
	error = rsync_queue(&module->key.rsync, module->path);
	return error ? error : EBUSY;
}

static int
dl_rrdp(struct cache_node *notif)
{
	bool changed;
	int error;

	error = rrdp_update(&notif->key.http, notif->path, notif->success_ts,
	    &changed, &notif->rrdp);
	if (error)
		return error;

	if (changed)
		notif->success_ts = notif->attempt_ts;
	return 0;
}

static int
dl_http(struct cache_node *file)
{
	bool changed;
	int error;

	error = http_download(&file->key.http, file->path,
	    file->success_ts, &changed);
	if (error)
		return error;

	if (changed)
		file->success_ts = file->attempt_ts;
	return 0;
}

/* Caller must lock @tbl->lock */
static struct cache_node *
find_node(struct cache_table *tbl, char const *url, size_t urlen)
{
	struct cache_node *node;
	HASH_FIND(hh, tbl->nodes, url, urlen, node);
	return node;
}

static struct cache_node *
provide_node(struct cache_table *tbl, struct uri const *http,
   struct uri const *rsync)
{
	struct node_key key;
	struct cache_node *node;

	if (!init_node_key(&key, http, rsync)) {
		pr_val_debug("Can't build node identifier: Both HTTP and rsync URLs are NULL.");
		return NULL;
	}

	node = find_node(tbl, key.id, key.idlen);
	if (node) {
		free(key.id);
		return node;
	}

	node = pzalloc(sizeof(struct cache_node));
	node->key = key;
	node->path = cseq_next(&tbl->seq);
	if (!node->path) {
		free(node);
		free(key.id);
		return NULL;
	}

	HASH_ADD_KEYPTR(hh, tbl->nodes, node->key.id, node->key.idlen, node);
	return node;

}

static void
rm_metadata(struct cache_node *node)
{
	char *filename;
	int error;

	filename = str_concat(node->path, ".json");
	pr_op_debug("rm %s", filename);
	if (unlink(filename) < 0) {
		error = errno;
		if (error == ENOENT)
			pr_op_debug("%s already doesn't exist.", filename);
		else
			pr_op_warn("Cannot rm %s: %s", filename, strerror(errno));
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
	filename = str_concat(node->path, ".json");

	pr_op_debug("echo \"$json\" > %s", filename);
	if (json_dump_file(json, filename, JSON_INDENT(2)))
		pr_op_err("Unable to write %s; unknown cause.", filename);

	free(filename);
	json_decref(json);
}

/*
 * @uri is either a caRepository or a rpkiNotify
 * By contract, only sets @result on return 0.
 * By contract, @result->state will be DLS_FRESH on return 0.
 */
static int
do_refresh(struct cache_table *tbl, struct uri const *uri,
    struct cache_node **result)
{
	struct uri module;
	struct cache_node *node;
	bool downloaded = false;

	pr_val_debug("Trying %s (online)...", uri_str(uri));

	if (!tbl->enabled) {
		pr_val_debug("Protocol disabled.");
		return ESRCH;
	}

	if (tbl == &cache.rsync) {
		if (!get_rsync_module(uri, &module))
			return EINVAL;
		mutex_lock(&tbl->lock);
		node = provide_node(tbl, NULL, &module);
	} else {
		mutex_lock(&tbl->lock);
		node = provide_node(tbl, uri, NULL);
	}
	if (!node) {
		mutex_unlock(&tbl->lock);
		return EINVAL;
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
		node->dlerr = tbl->download(node);
		if (node->dlerr == EBUSY)
			goto ongoing;
		write_metadata(node);
		downloaded = true;

		mutex_lock(&tbl->lock);
		node->state = DLS_FRESH;
		break;
	case DLS_ONGOING:
ongoing:	mutex_unlock(&tbl->lock);
		pr_val_debug("Refresh ongoing.");
		return EBUSY;
	case DLS_FRESH:
		break;
	default:
		pr_crit("Unknown node state: %d", node->state);
	}

	mutex_unlock(&tbl->lock);
	/* node->state is guaranteed to be DLS_FRESH at this point. */

	if (downloaded) /* Kickstart tasks that fell into DLS_ONGOING */
		task_wakeup_dormants();

	if (node->dlerr != 0) {
		pr_val_debug("Refresh failed.");
		return node->dlerr;
	}

	pr_val_debug("Refresh succeeded.");
	*result = node;
	return 0;
}

static struct cache_node *
find_rrdp_fallback_node(struct sia_uris *sias)
{
	struct node_key key;
	struct cache_node *result;

	if (!uri_str(&sias->rpkiNotify) || !uri_str(&sias->caRepository))
		return NULL;

	init_rrdp_fallback_key(&key, &sias->rpkiNotify, &sias->caRepository);
	result = find_node(&cache.fallback, key.id, key.idlen);
	free(key.id);

	return result;
}

static struct cache_node *
get_fallback(struct sia_uris *sias)
{
	struct cache_node *rrdp;
	struct cache_node *rsync;

	rrdp = find_rrdp_fallback_node(sias);
	rsync = find_node(&cache.fallback, uri_str(&sias->caRepository),
	    uri_len(&sias->caRepository));

	if (rrdp == NULL)
		return rsync;
	if (rsync == NULL)
		return rrdp;
	return (difftime(rsync->success_ts, rrdp->success_ts) > 0) ? rsync : rrdp;
}

/* Do not free nor modify the result. */
char *
cache_refresh_by_url(struct uri const *url)
{
	struct cache_node *node = NULL;

	// XXX review result signs

	if (uri_is_https(url))
		do_refresh(&cache.https, url, &node);
	else if (uri_is_rsync(url))
		do_refresh(&cache.rsync, url, &node);

	return node ? node->path : NULL;
}

/*
 * HTTPS (TAs) and rsync only; don't use this for RRDP.
 * Do not free nor modify the result.
 */
char *
cache_get_fallback(struct uri const *url)
{
	struct cache_node *node;

	/*
	 * The fallback table is read-only until the cleanup.
	 * Mutex not needed here.
	 */

	pr_val_debug("Trying %s (offline)...", uri_str(url));

	node = find_node(&cache.fallback, uri_str(url), uri_len(url));
	if (!node) {
		pr_val_debug("Cache data unavailable.");
		return NULL;
	}

	return node->path;
}

/*
 * Attempts to refresh the RPP described by @sias, returns the resulting
 * repository's mapper.
 *
 * XXX Need to normalize the sias.
 * XXX Fallback only if parent is fallback
 */
int
cache_refresh_by_sias(struct sia_uris *sias, struct cache_cage **result)
{
	struct cache_node *node;
	struct cache_cage *cage;
	struct uri rpkiNotify;

	// XXX Make sure somewhere validates rpkiManifest matches caRepository.
	// XXX review result signs

	/* Try RRDP + optional fallback */
	if (uri_str(&sias->rpkiNotify) != NULL) {
		switch (do_refresh(&cache.rrdp, &sias->rpkiNotify, &node)) {
		case 0:
			rpkiNotify = sias->rpkiNotify;
			goto refresh_success;
		case EBUSY:
			return EBUSY;
		}
	}

	/* Try rsync + optional fallback */
	switch (do_refresh(&cache.rsync, &sias->caRepository, &node)) {
	case 0:
		memset(&rpkiNotify, 0, sizeof(rpkiNotify));
		goto refresh_success;
	case EBUSY:
		return EBUSY;
	}

	/* Try fallback only */
	node = get_fallback(sias);
	if (!node)
		return EINVAL; /* Nothing to work with */

	*result = cage = pzalloc(sizeof(struct cache_cage));
	cage->fallback = node;
	return 0;

refresh_success:
	*result = cage = pzalloc(sizeof(struct cache_cage));
	cage->rpkiNotify = rpkiNotify;
	cage->refresh = node;
	cage->fallback = get_fallback(sias);
	return 0;
}

static char const *
node2file(struct cache_node const *node, struct uri const *url)
{
	if (node == NULL)
		return NULL;
	// XXX RRDP is const, rsync needs to be freed
	return (node->rrdp)
	    ? /* RRDP  */ rrdp_file(node->rrdp, url)
	    : /* rsync */ path_join(node->path, strip_rsync_module(uri_str(url)));
}

char const *
cage_map_file(struct cache_cage *cage, struct uri const *url)
{
	/*
	 * Remember: In addition to honoring the consts of cache->refresh and
	 * cache->fallback, anything these structures point to MUST NOT be
	 * modified either.
	 */

	char const *file;

	file = node2file(cage->refresh, url);
	if (!file)
		file = node2file(cage->fallback, url);

	return file;
}

/* Returns true if fallback should be attempted */
bool
cage_disable_refresh(struct cache_cage *cage)
{
	/*
	 * Remember: In addition to honoring the consts of cache->refresh and
	 * cache->fallback, anything these structures point to MUST NOT be
	 * modified either.
	 */

	bool enabled = (cage->refresh != NULL);
	cage->refresh = NULL;

	if (cage->fallback == NULL) {
		pr_val_debug("There is no fallback.");
		return false;
	}
	if (!enabled) {
		pr_val_debug("Fallback exhausted.");
		return false;
	}

	pr_val_debug("Attempting fallback.");
	return true;
}

struct mft_meta const *
cage_mft_fallback(struct cache_cage *cage)
{
	return cage->mft;
}

/*
 * Steals ownership of @rpp->files, @rpp->nfiles and @rpp->mft.num, but they're
 * not going to be modified nor deleted until the cache cleanup.
 */
void
cache_commit_rpp(struct uri const *rpkiNotify, struct uri const *caRepository,
    struct rpp *rpp)
{
	struct cache_commit *commit;

	commit = pmalloc(sizeof(struct cache_commit));
	uri_copy(&commit->rpkiNotify, rpkiNotify);
	uri_copy(&commit->caRepository, caRepository);
	commit->files = rpp->files;
	commit->nfiles = rpp->nfiles;
	INTEGER_move(&commit->mft.num, &rpp->mft.num);
	commit->mft.update = rpp->mft.update;

	mutex_lock(&commits_lock);
	STAILQ_INSERT_TAIL(&commits, commit, lh);
	mutex_unlock(&commits_lock);

	rpp->files = NULL;
	rpp->nfiles = 0;
}

void
cache_commit_file(struct cache_mapping *map)
{
	struct cache_commit *commit;

	commit = pzalloc(sizeof(struct cache_commit));
	memset(&commit->rpkiNotify, 0, sizeof(commit->rpkiNotify));
	memset(&commit->caRepository, 0, sizeof(commit->caRepository));
	commit->files = pmalloc(sizeof(*map));
	uri_copy(&commit->files[0].url, &map->url);
	commit->files[0].path = pstrdup(map->path);
	commit->nfiles = 1;
	memset(&commit->mft, 0, sizeof(commit->mft));

	mutex_lock(&commits_lock);
	STAILQ_INSERT_TAIL(&commits, commit, lh);
	mutex_unlock(&commits_lock);
}

void
rsync_finished(struct uri const *url, char const *path)
{
	struct cache_node *node;

	mutex_lock(&cache.rsync.lock);

	node = find_node(&cache.rsync, uri_str(url), uri_len(url));
	if (node == NULL) {
		mutex_unlock(&cache.rsync.lock);
		pr_op_err("rsync '%s -> %s' finished, but cache node does not exist.",
		    uri_str(url), path);
		return;
	}
	if (node->state != DLS_ONGOING)
		pr_op_warn("rsync '%s -> %s' finished, but existing node was not in ONGOING state.",
		    uri_str(url), path);

	node->state = DLS_FRESH;
	node->dlerr = 0;
	node->success_ts = node->attempt_ts;
	mutex_unlock(&cache.rsync.lock);

	task_wakeup_dormants();
}

struct uri const *
cage_rpkiNotify(struct cache_cage *cage)
{
	return &cage->rpkiNotify;
}

static void
cachent_print(struct cache_node *node)
{
	if (!node)
		return;

	printf("\thttp:%s rsync:%s (%s): ", uri_str(&node->key.http),
	    uri_str(&node->key.rsync), node->path);
	switch (node->state) {
	case DLS_OUTDATED:
		printf("stale ");
		break;
	case DLS_ONGOING:
		printf("downloading ");
		break;
	case DLS_FRESH:
		printf("fresh (errcode %d) ", node->dlerr);
		break;
	}

	printf("attempt:%lx success:%lx ", node->attempt_ts, node->success_ts);
	printf("mftUpdate:%lx ", node->mft.update);
	rrdp_print(node->rrdp);
	printf("\n");
}

static void
table_print(struct cache_table *tbl)
{
	struct cache_node *node, *tmp;

	printf("%s enabled:%d seq:%s/%lx\n",
	    tbl->name, tbl->enabled,
	    tbl->seq.prefix, tbl->seq.next_id);
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

static bool
is_fallback(char const *path)
{
	return str_starts_with(path, "fallback/");
}

/* Hard-links @rpp's approved files into the fallback directory. */
static void
commit_rpp(struct cache_commit *commit, struct cache_node *fb)
{
	struct cache_mapping *src;
	char const *dst;
	array_index i;

	INTEGER_move(&fb->mft.num, &commit->mft.num);
	fb->mft.update = commit->mft.update;

	for (i = 0; i < commit->nfiles; i++) {
		src = commit->files + i;

		if (is_fallback(src->path))
			continue;

		/*
		 * (fine)
		 * Note, this is accidentally working perfectly for rsync too.
		 * Might want to rename some of this.
		 */
		dst = rrdp_create_fallback(fb->path, &fb->rrdp, &src->url);
		if (!dst)
			goto skip;

		file_ln(src->path, dst);

skip:		free(src->path);
		src->path = pstrdup(dst);
	}
}

/* Deletes abandoned (ie. no longer ref'd by manifests) fallback hard links. */
static void
discard_trash(struct cache_commit *commit, struct cache_node *fallback)
{
	DIR *dir;
	struct dirent *file;
	char *file_path;
	array_index i;

	dir = opendir(fallback->path);
	if (dir == NULL) {
		pr_op_err("opendir() error: %s", strerror(errno));
		return;
	}

	FOREACH_DIR_FILE(dir, file) {
		if (S_ISDOTS(file))
			continue;

		/*
		 * TODO (fine) Bit slow; wants a hash table,
		 * and maybe skip @file_path's reallocation.
		 */

		file_path = path_join(fallback->path, file->d_name);

		for (i = 0; i < commit->nfiles; i++) {
			if (commit->files[i].path == NULL)
				continue;
			if (strcmp(file_path, commit->files[i].path) == 0)
				goto next;
		}

		/*
		 * Uh... maybe keep the file until an expiration threshold?
		 * None of the current requirements seem to mandate it.
		 * It sounds pretty unreasonable for a signed valid manifest to
		 * "forget" a file, then legitimately relist it without actually
		 * providing it.
		 */
		pr_op_debug("Removing hard link: %s", file_path);
		if (unlink(file_path) < 0)
			pr_op_warn("Could not unlink %s: %s",
			    file_path, strerror(errno));

next:		free(file_path);
	}

	if (errno)
		pr_op_err("Fallback directory traversal errored: %s",
		    strerror(errno));
	closedir(dir);
}

static void
commit_fallbacks(time_t now)
{
	struct cache_commit *commit;
	struct cache_node *fb;
	array_index i;
	int error;

	while (!STAILQ_EMPTY(&commits)) {
		commit = STAILQ_FIRST(&commits);
		STAILQ_REMOVE_HEAD(&commits, lh);

		if (uri_str(&commit->caRepository) != NULL) {
			pr_op_debug("Creating fallback for %s (%s)",
			    uri_str(&commit->caRepository),
			    uri_str(&commit->rpkiNotify));

			fb = provide_node(&cache.fallback,
			    &commit->rpkiNotify,
			    &commit->caRepository);
			fb->success_ts = now;

			pr_op_debug("mkdir -f %s", fb->path);
			if (mkdir(fb->path, CACHE_FILEMODE) < 0) {
				error = errno;
				if (error != EEXIST) {
					pr_op_err("Cannot create '%s': %s",
					    fb->path, strerror(error));
					goto skip;
				}

				rm_metadata(fb); /* error == EEXIST */
			}

			commit_rpp(commit, fb);
			discard_trash(commit, fb);

		} else { /* TA */
			struct cache_mapping *map = &commit->files[0];

			pr_op_debug("Creating fallback for %s",
			    uri_str(&map->url));

			fb = provide_node(&cache.fallback, &map->url, NULL);
			fb->success_ts = now;
			if (is_fallback(map->path))
				goto freshen;

			file_ln(map->path, fb->path);
		}

		write_metadata(fb);

freshen:	fb->state = DLS_FRESH;
skip:		uri_cleanup(&commit->rpkiNotify);
		uri_cleanup(&commit->caRepository);
		for (i = 0; i < commit->nfiles; i++) {
			uri_cleanup(&commit->files[i].url);
			free(commit->files[i].path);
		}
		free(commit->files);
		mftm_cleanup(&commit->mft);
		free(commit);
	}
}

static void
remove_abandoned(struct cache_table *table, struct cache_node *node, void *arg)
{
	time_t now;

	if (node->state == DLS_FRESH)
		return;

	now = *((time_t *)arg);
	if (difftime(node->attempt_ts + cfg_cache_threshold(), now) < 0) {
		rm_metadata(node);
		file_rm_rf(node->path);
		delete_node(table, node, NULL);
	}
}

static void
remove_orphaned_nodes(struct cache_table *table, struct cache_node *node,
    void *arg)
{
	if (file_exists(node->path) == ENOENT) {
		pr_op_debug("Missing file; deleting node: %s", node->path);
		delete_node(table, node, NULL);
	}
}

static void
remove_orphaned_files(void)
{
	// XXX
}

/* Deletes obsolete files and nodes from the cache. */
static void
cleanup_cache(void)
{
	time_t now = time_fatal();

	/* Delete the entirety of cache/tmp/. */
	pr_op_debug("Cleaning up temporal files.");
	file_rm_rf(CACHE_TMPDIR);

	/*
	 * Ensure valid RPPs and TAs are linked in fallback,
	 * by hard-linking the new files.
	 */
	pr_op_debug("Committing fallbacks.");
	commit_fallbacks(now);

	/*
	 * Delete refresh nodes that haven't been downloaded in a while,
	 * and fallback nodes that haven't been valid in a while.
	 */
	pr_op_debug("Cleaning up abandoned cache files.");
	foreach_node(remove_abandoned, &now);

	/* (Paranoid) Delete nodes that are no longer mapped to files. */
	pr_op_debug("Cleaning up orphaned nodes.");
	foreach_node(remove_orphaned_nodes, NULL);

	/* (Paranoid) Delete files that are no longer mapped to nodes. */
	pr_op_debug("Cleaning up orphaned files.");
	remove_orphaned_files();
}

void
cache_commit(void)
{
	cleanup_cache();
	file_write_txt(METAFILE, "{ \"fort-version\": \"" PACKAGE_VERSION "\" }");
	unlock_cache();
	flush_nodes();
}

void
sias_init(struct sia_uris *sias)
{
	memset(sias, 0, sizeof(*sias));
}

void
sias_cleanup(struct sia_uris *sias)
{
	uri_cleanup(&sias->caRepository);
	uri_cleanup(&sias->rpkiNotify);
	uri_cleanup(&sias->rpkiManifest);
	uri_cleanup(&sias->crldp);
	uri_cleanup(&sias->caIssuers);
	uri_cleanup(&sias->signedObject);
}
