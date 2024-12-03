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

/*
 * This is a delicate structure; pay attention.
 *
 * During the multithreaded stage of the validation cycle, the entire cache_node
 * (except @hh) becomes (effectively) constant when @state becomes DLS_FRESH.
 *
 * The cache (ie. this module) only hands the node to the validation code
 * (through cache_cage) when @state becomes DLS_FRESH.
 *
 * This is intended to allow the validation code to read the remaining fields
 * (all except @hh) without having to hold the table mutex.
 *
 * C cannot entirely ensure the node remains constant after it's handed outside;
 * this must be done through careful coding and review.
 */
struct cache_node {
	struct cache_mapping map;

	enum node_state state;
	/* Result code of recent dl attempt (DLS_FRESH only) */
	int dlerr;
	time_t attempt_ts;	/* Refresh: Dl attempt. Fallback: Commit */
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
	char const *rpkiNotify;
	struct mft_meta *mft;		/* Fallback */
};

struct cache_commit {
	char *rpkiNotify;
	char *caRepository;
	struct cache_mapping *files;
	size_t nfiles;
	struct mft_meta mft;		/* RPPs commits only */
	STAILQ_ENTRY(cache_commit) lh;
};

static STAILQ_HEAD(cache_commits, cache_commit) commits = STAILQ_HEAD_INITIALIZER(commits);
static pthread_mutex_t commits_lock = PTHREAD_MUTEX_INITIALIZER;

#define LOCKFILE ".lock"
#define INDEX_FILE "index.json"
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

	HASH_DEL(tbl->nodes, node);

	map_cleanup(&node->map);
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

char *
get_rsync_module(char const *url)
{
	array_index u;
	unsigned int slashes;

	slashes = 0;
	for (u = 0; url[u] != 0; u++)
		if (url[u] == '/') {
			slashes++;
			if (slashes == 4)
				return pstrndup(url, u);
		}

	if (slashes == 3 && url[u - 1] != '/')
		return pstrdup(url);

	pr_val_err("Url '%s' does not appear to have an rsync module.", url);
	return NULL;
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

static int dl_rsync(struct cache_node *);
static int dl_http(struct cache_node *);
static int dl_rrdp(struct cache_node *);

static void
init_table(struct cache_table *tbl, char *name, bool enabled, dl_cb dl)
{
	memset(tbl, 0, sizeof(*tbl));
	tbl->name = name;
	tbl->enabled = enabled;
	cseq_init(&tbl->seq, name, false);
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

static struct cache_node *
json2node(json_t *json)
{
	struct cache_node *node;
	char const *str;
	json_t *rrdp;
	int error;

	node = pzalloc(sizeof(struct cache_node));

	if (json_get_str(json, "url", &str))
		goto fail;
	node->map.url = pstrdup(str);
	if (json_get_str(json, "path", &str))
		goto fail;
	node->map.path = pstrdup(str);
	error = json_get_ts(json, "attempt", &node->attempt_ts);
	if (error != 0 && error != ENOENT)
		goto fail;
	error = json_get_ts(json, "success", &node->success_ts);
	if (error != 0 && error != ENOENT)
		goto fail;
	error = json_get_bigint(json, "mftNum", &node->mft.num);
	if (error < 0)
		goto fail;
	error = json_get_ts(json, "mftUpdate", &node->mft.update);
	if (error < 0)
		goto fail;
	error = json_get_object(json, "rrdp", &rrdp);
	if (error < 0)
		goto fail;
	if (error == 0 && rrdp_json2state(rrdp, &node->rrdp))
		goto fail;

	return node;

fail:	map_cleanup(&node->map);
	return NULL;
}

static void
json2tbl(json_t *root, struct cache_table *tbl)
{
	json_t *array, *child;
	int index;
	struct cache_node *node;
	size_t urlen;

	// XXX load (and save) seqs
	if (json_get_ulong(root, "next", &tbl->seq.next_id))
		return;
	if (json_get_array(root, tbl->name, &array))
		return;

	json_array_foreach(array, index, child) {
		node = json2node(child);
		if (node == NULL)
			continue;
		urlen = strlen(node->map.url);
		// XXX worry about dupes
		HASH_ADD_KEYPTR(hh, tbl->nodes, node->map.url, urlen, node);
	}
}

static int
load_index_file(void)
{
	json_t *root;
	json_error_t jerr;
	char const *file_version;
	int error;

	pr_op_debug("Loading " INDEX_FILE "...");

	root = json_load_file(INDEX_FILE, 0, &jerr);
	if (root == NULL) {
		if (json_error_code(&jerr) == json_error_cannot_open_file)
			pr_op_debug(INDEX_FILE " does not exist.");
		else
			pr_op_err("Json parsing failure at %s (%d:%d): %s",
			    INDEX_FILE, jerr.line, jerr.column, jerr.text);
		goto fail;
	}
	if (json_typeof(root) != JSON_OBJECT) {
		pr_op_err("The root tag of " INDEX_FILE " is not an object.");
		goto fail;
	}

	error = json_get_str(root, TAGNAME_VERSION, &file_version);
	if (error) {
		if (error > 0)
			pr_op_err(INDEX_FILE " is missing the '"
			    TAGNAME_VERSION "' tag.");
		goto fail;
	}
	if (strcmp(file_version, PACKAGE_VERSION) != 0)
		goto fail;

	json2tbl(root, &cache.rsync);
	json2tbl(root, &cache.https);
	json2tbl(root, &cache.rrdp);
	json2tbl(root, &cache.fallback);

	json_decref(root);
	pr_op_debug(INDEX_FILE " loaded.");
	return 0;

fail:	json_decref(root);
	return EINVAL;
}

int
cache_prepare(void)
{
	int error;

	error = lock_cache();
	if (error)
		return error;

	if (load_index_file() != 0) {
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

static json_t *
node2json(struct cache_node *node)
{
	json_t *json;

	json = json_obj_new();
	if (json == NULL)
		return NULL;

	if (json_add_str(json, "url", node->map.url))
		goto fail;
	if (json_add_str(json, "path", node->map.path))
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

static json_t *
tbl2json(struct cache_table *tbl)
{
	struct json_t *json, *nodes;
	struct cache_node *node, *tmp;

	json = json_obj_new();
	if (!json)
		return NULL;

	if (json_add_ulong(json, "next", tbl->seq.next_id))
		goto fail;

	nodes = json_array_new();
	if (!nodes)
		goto fail;
	if (json_object_add(json, "nodes", nodes))
		goto fail;

	HASH_ITER(hh, tbl->nodes, node, tmp)
		if (json_array_add(nodes, node2json(node)))
			goto fail;

	return json;

fail:	json_decref(json);
	return NULL;
}

static json_t *
build_index_file(void)
{
	json_t *json;

	json = json_obj_new();
	if (json == NULL)
		return NULL;

	if (json_object_add(json, TAGNAME_VERSION, json_str_new(PACKAGE_VERSION)))
		goto fail;
	if (json_object_add(json, "rsync", tbl2json(&cache.rsync)))
		goto fail;
	if (json_object_add(json, "https", tbl2json(&cache.https)))
		goto fail;
	if (json_object_add(json, "rrdp", tbl2json(&cache.rrdp)))
		goto fail;
	if (json_object_add(json, "fallback", tbl2json(&cache.fallback)))
		goto fail;

	return json;

fail:	json_decref(json);
	return NULL;
}

static void
write_index_file(void)
{
	struct json_t *json;

	json = build_index_file();
	if (json == NULL)
		return;

	if (json_dump_file(json, INDEX_FILE, JSON_INDENT(2)))
		pr_op_err("Unable to write " INDEX_FILE "; unknown cause.");

	json_decref(json);
}

static int
dl_rsync(struct cache_node *module)
{
	int error;

	error = rsync_download(module->map.url, module->map.path);
	if (error)
		return error;

	module->success_ts = module->attempt_ts;
	return 0;
}

static int
dl_rrdp(struct cache_node *notif)
{
	bool changed;
	int error;

	error = rrdp_update(&notif->map, notif->success_ts,
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

	error = http_download(file->map.url, file->map.path,
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
	node->map.path = cseq_next(&tbl->seq);
	if (!node->map.path) {
		free(node->map.url);
		free(node);
		return NULL;
	}
	HASH_ADD_KEYPTR(hh, tbl->nodes, node->map.url, urlen, node);

	return node;
}

/*
 * @uri is either a caRepository or a rpkiNotify
 * By contract, only sets @result on return 0.
 * By contract, @result->state will be DLS_FRESH on return 0.
 */
static int
do_refresh(struct cache_table *tbl, char const *uri, struct cache_node **result)
{
	struct cache_node *node;
	bool downloaded = false;

	pr_val_debug("Trying %s (online)...", uri);

	if (!tbl->enabled) {
		pr_val_debug("Protocol disabled.");
		return ESRCH;
	}

	if (tbl == &cache.rsync) {
		char *module = get_rsync_module(uri);
		if (module == NULL)
			return EINVAL;
		mutex_lock(&tbl->lock);
		node = provide_node(tbl, module);
		free(module);
	} else {
		mutex_lock(&tbl->lock);
		node = provide_node(tbl, uri);
	}
	if (!node) {
		mutex_unlock(&tbl->lock);
		return EINVAL;
	}

	switch (node->state) {
	case DLS_OUTDATED:
		node->state = DLS_ONGOING;
		mutex_unlock(&tbl->lock);

		node->attempt_ts = time_fatal();
		node->dlerr = tbl->download(node);
		downloaded = true;

		mutex_lock(&tbl->lock);
		node->state = DLS_FRESH;
		break;
	case DLS_ONGOING:
		mutex_unlock(&tbl->lock);
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
		task_wakeup_busy();

	if (node->dlerr != 0) {
		pr_val_debug("Refresh failed.");
		return node->dlerr;
	}

	pr_val_debug("Refresh succeeded.");
	*result = node;
	return 0;
}

static char *
get_rrdp_fallback_key(char const *context, char const *caRepository)
{
	char *key;
	size_t keylen;
	int written;

	keylen = strlen(context) + strlen(caRepository) + 2;
	key = pmalloc(keylen);

	written = snprintf(key, keylen, "%s\t%s", context, caRepository);
	if (written != keylen - 1)
		pr_crit("find_rrdp_fallback_node: %zu %d %s %s",
		    keylen, written, context, caRepository);

	return key;
}

static struct cache_node *
find_rrdp_fallback_node(struct sia_uris *sias)
{
	char *key;
	struct cache_node *result;

	if (!sias->rpkiNotify || !sias->caRepository)
		return NULL;

	key = get_rrdp_fallback_key(sias->rpkiNotify, sias->caRepository);
	result = find_node(&cache.fallback, key, strlen(key));
	free(key);

	return result;
}

static struct cache_node *
get_fallback(struct sia_uris *sias)
{
	struct cache_node *rrdp;
	struct cache_node *rsync;

	rrdp = find_rrdp_fallback_node(sias);
	rsync = find_node(&cache.fallback, sias->caRepository,
	    strlen(sias->caRepository));

	if (rrdp == NULL)
		return rsync;
	if (rsync == NULL)
		return rrdp;
	return (difftime(rsync->success_ts, rrdp->success_ts) > 0) ? rsync : rrdp;
}

/* Do not free nor modify the result. */
char *
cache_refresh_by_url(char const *url)
{
	struct cache_node *node = NULL;

	// XXX review result signs
	// XXX Normalize @url

	if (url_is_https(url))
		do_refresh(&cache.https, url, &node);
	else if (url_is_rsync(url))
		do_refresh(&cache.rsync, url, &node);

	return node ? node->map.path : NULL;
}

/*
 * HTTPS (TAs) and rsync only; don't use this for RRDP.
 * Do not free nor modify the result.
 */
char *
cache_get_fallback(char const *url)
{
	struct cache_node *node;

	/*
	 * The fallback table is read-only until the cleanup.
	 * Mutex not needed here.
	 */

	pr_val_debug("Trying %s (offline)...", url);

	node = find_node(&cache.fallback, url, strlen(url));
	if (!node) {
		pr_val_debug("Cache data unavailable.");
		return NULL;
	}

	return node->map.path;
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
	char const *rpkiNotify;

	// XXX Make sure somewhere validates rpkiManifest matches caRepository.
	// XXX review result signs
	// XXX normalize rpkiNotify & caRepository?

	/* Try RRDP + optional fallback */
	if (sias->rpkiNotify) {
		switch (do_refresh(&cache.rrdp, sias->rpkiNotify, &node)) {
		case 0:
			rpkiNotify = sias->rpkiNotify;
			goto refresh_success;
		case EBUSY:
			return EBUSY;
		}
	}

	/* Try rsync + optional fallback */
	switch (do_refresh(&cache.rsync, sias->caRepository, &node)) {
	case 0:
		rpkiNotify = NULL;
		goto refresh_success;
	case EBUSY:
		return EBUSY;
	}

	/* Try fallback only */
	node = get_fallback(sias);
	if (!node)
		return EINVAL; /* Nothing to work with */

	*result = cage = pmalloc(sizeof(struct cache_cage));
	cage->refresh = NULL;
	cage->fallback = node;
	return 0;

refresh_success:
	*result = cage = pmalloc(sizeof(struct cache_cage));
	cage->rpkiNotify = rpkiNotify;
	cage->refresh = node;
	cage->fallback = get_fallback(sias);
	return 0;
}

static char const *
node2file(struct cache_node const *node, char const *url)
{
	if (node == NULL)
		return NULL;
	// XXX RRDP is const, rsync needs to be freed
	return (node->rrdp)
	    ? /* RRDP  */ rrdp_file(node->rrdp, url)
	    : /* rsync */ path_join(node->map.path, strip_rsync_module(url));
}

char const *
cage_map_file(struct cache_cage *cage, char const *url)
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
cache_commit_rpp(char const *rpkiNotify, char const *caRepository,
    struct rpp *rpp)
{
	struct cache_commit *commit;

	commit = pmalloc(sizeof(struct cache_commit));
	commit->rpkiNotify = rpkiNotify ? pstrdup(rpkiNotify) : NULL;
	commit->caRepository = pstrdup(caRepository);
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

	commit = pmalloc(sizeof(struct cache_commit));
	commit->rpkiNotify = NULL;
	commit->caRepository = NULL;
	commit->files = pmalloc(sizeof(*map));
	commit->files[0].url = pstrdup(map->url);
	commit->files[0].path = pstrdup(map->path);
	commit->nfiles = 1;
	memset(&commit->mft, 0, sizeof(commit->mft));

	mutex_lock(&commits_lock);
	STAILQ_INSERT_TAIL(&commits, commit, lh);
	mutex_unlock(&commits_lock);
}

char const *
cage_rpkiNotify(struct cache_cage *cage)
{
	return cage->rpkiNotify;
}

static void
cachent_print(struct cache_node *node)
{
	if (!node)
		return;

	printf("\t%s (%s): ", node->map.url, node->map.path);
	switch (node->state) {
	case DLS_OUTDATED:
		printf("stale");
		break;
	case DLS_ONGOING:
		printf("downloading");
		break;
	case DLS_FRESH:
		printf("fresh (errcode %d)", node->dlerr);
		break;
	}
	printf("\n");
}

static void
table_print(struct cache_table *tbl)
{
	struct cache_node *node, *tmp;

	if (HASH_COUNT(tbl->nodes) == 0)
		return;

	printf("    %s (%s):\n", tbl->name, tbl->enabled ? "enabled" : "disabled");
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
		dst = rrdp_create_fallback(fb->map.path, &fb->rrdp, src->url);
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

	dir = opendir(fallback->map.path);
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

		file_path = path_join(fallback->map.path, file->d_name);

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

	while (!STAILQ_EMPTY(&commits)) {
		commit = STAILQ_FIRST(&commits);
		STAILQ_REMOVE_HEAD(&commits, lh);

		if (commit->caRepository) {
			pr_op_debug("Creating fallback for %s (%s)",
			    commit->caRepository, commit->rpkiNotify);

			if (commit->rpkiNotify) {
				char *key;
				key = get_rrdp_fallback_key(commit->rpkiNotify,
				    commit->caRepository);
				fb = provide_node(&cache.fallback, key);
				free(key);
			} else {
				fb = provide_node(&cache.fallback,
				    commit->caRepository);
			}

			if (file_mkdir(fb->map.path, true) != 0)
				goto skip;

			commit_rpp(commit, fb);
			discard_trash(commit, fb);

		} else { /* TA */
			struct cache_mapping *map = &commit->files[0];

			pr_op_debug("Creating fallback for %s", map->url);

			fb = provide_node(&cache.fallback, map->url);
			if (is_fallback(map->path))
				goto freshen;

			file_ln(map->path, fb->map.path);
		}

freshen:	fb->state = DLS_FRESH;
		fb->attempt_ts = fb->success_ts = now;
skip:		free(commit->rpkiNotify);
		free(commit->caRepository);
		for (i = 0; i < commit->nfiles; i++) {
			free(commit->files[i].url);
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
		file_rm_rf(node->map.path);
		delete_node(table, node, NULL);
	}
}

static void
remove_orphaned_nodes(struct cache_table *table, struct cache_node *node,
    void *arg)
{
	if (file_exists(node->map.path) == ENOENT) {
		pr_op_debug("Missing file; deleting node: %s", node->map.path);
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
	write_index_file();
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
	free(sias->caRepository);
	free(sias->rpkiNotify);
	free(sias->rpkiManifest);
	free(sias->crldp);
	free(sias->caIssuers);
	free(sias->signedObject);
}
