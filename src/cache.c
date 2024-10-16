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
#include "types/array.h"
#include "types/path.h"
#include "types/url.h"
#include "types/uthash.h"

struct cache_node {
	struct cache_mapping map;

	/* XXX change to boolean? */
	int fresh;		/* Refresh already attempted? */
	int dlerr;		/* Result code of recent download attempt */
	time_t mtim;		/* Last successful download time, or zero */

	struct rrdp_state *rrdp;

	UT_hash_handle hh;	/* Hash table hook */
};

typedef int (*dl_cb)(struct cache_node *rpp);

struct cache_table {
	char *name;
	bool enabled;
	struct cache_sequence seq;
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

/* "Is the lockfile ours?" */
static volatile sig_atomic_t lockfile_owned;

struct cache_cage {
	struct cache_node *refresh;
	struct cache_node *fallback;
};

struct cache_commit {
	char *caRepository;
	struct cache_mapping *files;
	size_t nfiles;
	STAILQ_ENTRY(cache_commit) lh;
};

STAILQ_HEAD(cache_commits, cache_commit) commits = STAILQ_HEAD_INITIALIZER(commits);

#define LOCKFILE ".lock"
#define INDEX_FILE "index.json"
#define TAGNAME_VERSION "fort-version"

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

	map_cleanup(&node->map);
	rrdp_state_free(node->rrdp);
	free(node);
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

void
cache_teardown(void)
{
	/* Empty */
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
	error = json_get_int(json, "dlerr", &node->dlerr);
	if (error != 0 && error != ENOENT)
		goto fail;
	error = json_get_ts(json, "mtim", &node->mtim);
	if (error != 0 && error != ENOENT)
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

fail:	cache_foreach(delete_node);
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
	if (node->dlerr && json_add_int(json, "dlerr", node->dlerr)) // XXX relevant?
		goto fail;
	if (node->mtim && json_add_ts(json, "mtim", node->mtim))
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

	error = rrdp_update(&notif->map, notif->mtim, &changed, &cache.rrdp.seq,
	    &notif->rrdp);
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

/* @uri is either a caRepository or a rpkiNotify */
static struct cache_node *
do_refresh(struct cache_table *tbl, char const *uri)
{
	struct cache_node *node;

	pr_val_debug("Trying %s (online)...", uri);

	if (!tbl->enabled) {
		pr_val_debug("Protocol disabled.");
		return NULL;
	}

	if (tbl == &cache.rsync) {
		char *module = get_rsync_module(uri);
		if (module == NULL)
			return NULL;
		node = provide_node(tbl, module);
		free(module);
	} else {
		node = provide_node(tbl, uri);
	}
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
	return (node && !node->dlerr) ? node->map.path : NULL;
}

/* Do not free nor modify the result. */
char *
cache_fallback_url(char const *url)
{
	struct cache_node *node;

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
struct cache_cage *
cache_refresh_sias(struct sia_uris *sias)
{
	struct cache_cage *cage;
	struct cache_node *node;

	// XXX Make sure somewhere validates rpkiManifest matches caRepository.
	// XXX mutex
	// XXX review result signs
	// XXX normalize rpkiNotify & caRepository?

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
	// XXX RRDP is const, rsync needs to be freed
	return (node->rrdp)
	    ? /* RRDP  */ rrdp_file(node->rrdp, url)
	    : /* rsync */ path_join(node->map.path, strip_rsync_module(url));
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

/* Returns true if fallback should be attempted */
bool
cage_disable_refresh(struct cache_cage *cage)
{
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

/*
 * Steals ownership of @rpp->files and @rpp->nfiles, but they're not going to be
 * modified nor deleted until the cache cleanup.
 */
void
cache_commit_rpp(char const *caRepository, struct rpp *rpp)
{
	struct cache_commit *commit;

	commit = pmalloc(sizeof(struct cache_commit));
	// XXX missing context
	commit->caRepository = pstrdup(caRepository);
	commit->files = rpp->files;
	commit->nfiles = rpp->nfiles;
	STAILQ_INSERT_TAIL(&commits, commit, lh);

	rpp->files = NULL;
	rpp->nfiles = 0;
}

void
cache_commit_file(struct cache_mapping *map)
{
	struct cache_commit *commit;

	commit = pmalloc(sizeof(struct cache_commit));
	// XXX missing context
	commit->caRepository = NULL;
	commit->files = pmalloc(sizeof(*map));
	commit->files[0].url = pstrdup(map->url);
	commit->files[0].path = pstrdup(map->path);
	commit->nfiles = 1;
	STAILQ_INSERT_TAIL(&commits, commit, lh);
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
	if (nftw(CACHE_TMPDIR, rmf, 32, FTW_DEPTH | FTW_PHYS))
		pr_op_warn("Cannot empty the cache's tmp directory: %s",
		    strerror(errno));
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

		pr_op_debug("Hard-linking: %s -> %s", src->path, dst);
		if (link(src->path, dst) < 0)
			pr_op_warn("Could not hard-link cache file: %s",
			    strerror(errno));

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
commit_fallbacks(void)
{
	struct cache_commit *commit;
	struct cache_node *fb, *tmp;
	array_index i;
	int error;

	while (!STAILQ_EMPTY(&commits)) {
		commit = STAILQ_FIRST(&commits);
		STAILQ_REMOVE_HEAD(&commits, lh);

		if (commit->caRepository) {
			fb = provide_node(&cache.fallback, commit->caRepository);

			if (file_mkdir(fb->map.path, true) != 0)
				goto skip;

			commit_rpp(commit, fb);
			discard_trash(commit, fb);

		} else { /* TA */
			struct cache_mapping *map = &commit->files[0];

			fb = provide_node(&cache.fallback, map->url);
			if (is_fallback(map->path))
				goto freshen;

			pr_op_debug("Hard-linking TA: %s -> %s",
			    map->path, fb->map.path);
			if (link(map->path, fb->map.path) < 0)
				pr_op_warn("Could not hard-link cache file: %s",
				    strerror(errno));
		}

freshen:	fb->fresh = 1;
skip:		free(commit->caRepository);
		for (i = 0; i < commit->nfiles; i++) {
			free(commit->files[i].url);
			free(commit->files[i].path);
		}
		free(commit->files);
		free(commit);
	}

	HASH_ITER(hh, cache.fallback.nodes, fb, tmp) {
		if (fb->fresh)
			continue;

		/*
		 * XXX This one, on the other hand, would definitely benefit
		 * from an expiration threshold.
		 */
		pr_op_debug("Removing orphaned fallback: %s", fb->map.path);
		error = file_rm_rf(fb->map.path);
		if (error)
			pr_op_warn("%s removal failed: %s",
			    fb->map.path, strerror(error));
		delete_node(&cache.fallback, fb);
	}
}

static void
remove_abandoned(void)
{
	// XXX no need to recurse anymore.
	/*
	nftw_root = cache.rsync;
	nftw("rsync", nftw_remove_abandoned, 32, FTW_DEPTH | FTW_PHYS); // XXX

	nftw_root = cache.https;
	nftw("https", nftw_remove_abandoned, 32, FTW_DEPTH | FTW_PHYS); // XXX
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

/*
 * Deletes unknown and old untraversed cached files, writes metadata into XML.
 */
static void
cleanup_cache(void)
{
	// XXX Review
	pr_op_debug("Cleaning up temporal files.");
	cleanup_tmp();

	pr_op_debug("Creating fallbacks for valid RPPs.");
	commit_fallbacks();

	pr_op_debug("Cleaning up old abandoned and unknown cache files.");
	remove_abandoned();

	pr_op_debug("Cleaning up orphaned nodes.");
	cache_foreach(remove_orphaned);
}

void
cache_commit(void)
{
	cleanup_cache();
	write_index_file();
	unlock_cache();
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
