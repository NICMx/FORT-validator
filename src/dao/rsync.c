#define _DEFAULT_SOURCE 1 /* DT_REG et al */

#include "dao/rsync.h"

#include <sys/types.h>
#include <dirent.h>

#include "cachefile.h"
#include "common.h"
#include "file.h"
#include "json_util.h"
#include "log.h"
#include "types/path.h"
#include "types/str.h"

enum rsync_dao_state {
	RDS_REFRESH,
	RDS_FALLBACK,
	RDS_DONE,
};

struct rsync_dao {
	struct uri caRepository;
	enum rsync_dao_state state;

	struct rsync_ctx *ctx;
	struct fallback *fb;
};

struct rsync_ctx {
	/*
	 * Path to the directory where we store Remote files.
	 * "Remote files" are our old*1 and mostly exact*2 cache clone of the
	 * server files.
	 *
	 * *1 "old" refers to the previous cycle. We included --compare-dest
	 *    in the current refresh; see @new_path.
	 * *2 "mostly exact" because we didn't rsync with --delete, so we may
	 *    have some extra stale files. We'll timeout during some cleanup
	 *    later.
	 */
	char *remote_path;

	/*
	 * Path to the directory where we store New files.
	 * "New files" are the delta files we downloaded during the refresh of
	 * the current cycle. (See rsync's --compare-dest.)
	 * We need to rsync with --compare-dest because we need to preserve
	 * fallbacks; we can't have rsync overriding files we may still need.
	 * New files will be "merged" into Remote files during the cleanup.
	 */
	char *new_path;

	/*
	 * Path to the directory where we store Fallback files.
	 * "Fallback files" are the ones we had to back up during the previous
	 * cleanup, because the remote repository removed them, even though we
	 * still need them.
	 */
	char *fb_path;

	/* Index of files in the Remote path */
	struct files_ht remote;
	/* Index of files in the New path */
	struct files_ht new;
	/* Hash table, indexed by caRepository */
	struct fallback_ht fbs;

	/* For fallback file names */
	struct cache_sequence fbseq;
};

static struct cache_file *
find_path_in_fallbacks(char const *path, struct fallback_ht *fbs)
{
	struct fallback *fb, *tmp1;
	struct cache_file_ref *ref, *tmp2;

	if (!fbs)
		return NULL;

	/* TODO (performance) The data structure is not great for this lookup */
	HASH_ITER(hh, fbs->ht, fb, tmp1)
		HASH_ITER(hh, fb->files.ht, ref, tmp2)
			if (strcmp(path, ref->file->map.path) == 0)
				return ref->file;

	return NULL;
}

static int
add_file(struct files_ht *table, struct cache_mapping *root, char *path,
    struct fallback_ht *fbs)
{
	unsigned char csum[EVP_MAX_MD_SIZE];
	size_t csumlen;

	char const *uri_path;
	char *uri_str;
	struct uri uri;
	struct cache_file *file;

	file = find_path_in_fallbacks(path, fbs);
	if (file) {
		filerefs_add_uri(table, file, 1);
		return 0;
	}

	if (hash_file(hash_get_sha256(), path, csum, &csumlen) != 0)
		return pr_err("Cannot checksum %s.", path);
	if (csumlen != SHA256_DIGEST_LENGTH)
		return pr_err("Bad checksum size: %zu", csumlen);

	uri_path = str_skip(path, root->path);
	if (!uri_path)
		return pr_err("Missing '%s' prefix: %s", root->path, path);
	uri_path = str_skip(uri_path, "/");
	if (!uri_path)
		return pr_err("Path is missing context: %s", path);
	uri_path = strchr(uri_path, '/');
	if (!uri_path)
		return pr_err("Path is missing context: %s", path);

	uri_str = path_join(uri_str(&root->url), uri_path);
	__uri_init(&uri, uri_str, strlen(uri_str));
	file = cachefile_create(&uri, path, path, csum);
	uri_cleanup(&uri);

	filerefs_add_uri(table, file, 0);
	return 0;
}

static int
index_files(struct cache_mapping *ctx_root, char const *root_path,
    struct files_ht *files, struct fallback_ht *fbs)
{
	struct string_arraylist dirs;
	DIR *dir;
	struct dirent *file;
	struct stat st;
	char *dirpath;
	char *filepath;
	int error;

	files->ht = NULL;
	stral_init(&dirs, 32);
	stral_add(&dirs, pstrdup(root_path));

	do {
		dirs.len--;
		dirpath = dirs.arr[dirs.len];

		dir = opendir(dirpath);
		if (!dir) {
			error = errno;
			if (error == ENOENT)
				continue;
			pr_err("Cannot open directory %s: %s",
			    dirpath, strerror(error));
			goto cancel;
		}

		FOREACH_DIR_FILE(dir, file) {
			if (S_ISDOTS(file))
				continue;

			filepath = path_join(dirpath, file->d_name);

			// FIXME not supported by all systems
			switch (file->d_type) {
			case DT_REG:
				error = add_file(files, ctx_root, filepath, fbs);
				if (error)
					goto cancel;
				filepath = NULL;
				break;

			case DT_DIR:
				stral_add(&dirs, filepath);
				filepath = NULL;
				break;

			case DT_UNKNOWN:
				if (lstat(filepath, &st) < 0)
					break; // FIXME maybe warning?
				if (S_ISREG(st.st_mode)) {
					error = add_file(files, ctx_root, filepath, fbs);
					if (error) {
						free(filepath);
						goto cancel;
					}
					filepath = NULL;
				} else if (S_ISDIR(st.st_mode)) {
					stral_add(&dirs, filepath);
					filepath = NULL;
				}
				break;
			}

			free(filepath);
		}

		error = errno;
		closedir(dir);

		if (error) {
			pr_err("Directory traversal interrupted: %s",
			    strerror(error));
			goto cancel;
		}

		free(dirpath);
	} while (dirs.len != 0);

	stral_cleanup(&dirs);
	return 0;

cancel:	free(dirpath);
	filerefs_clear(files, true);
	stral_cleanup(&dirs);
	return error;
}

int
rsync_reindex(struct rsync_ctx **_ctx, struct cache_mapping *root)
{
	struct rsync_ctx *ctx = *_ctx;
	int error;

	if (!ctx) {
		*_ctx = ctx = pzalloc(sizeof(struct rsync_ctx));
		ctx->remote_path = path_join(root->path, "rmt");
		ctx->new_path = path_join(root->path, "new");
		ctx->fb_path = path_join(root->path, "fbk");
		cseq_init(&ctx->fbseq, ctx->fb_path, 0, false);
	}

	error = index_files(root, ctx->remote_path, &ctx->remote, &ctx->fbs);
	if (error)
		goto ouch;
	error = index_files(root, ctx->new_path, &ctx->new, NULL);
	if (error)
		goto ouch;

	panic_on_fail(pthread_mutex_init(&ctx->fbs.lock, NULL),
	    "pthread_mutex_init");

	return 0;

ouch:	rsync_free(ctx);
	*_ctx = NULL;
	return error;
}

static int
mkdir_p(char *path, size_t offset)
{
	char *slash;
	int error;

	while ((slash = strchr(path + offset, '/')) != NULL) {
		*slash = 0;
		error = file_mkdir(path, true);
		if (error)
			return error;
		*slash = '/';
		offset = (slash - path) + 1;
	}

	return 0;
}

struct cachefile_array {
	struct cache_file **files; /* Pointer array */
	size_t count;
	size_t capacity;
};

struct cachefile_array
find_fallbacks(struct rsync_ctx *ctx, char *path)
{
	struct fallback *fb, *tmpf;
	struct cache_file_ref *ref, *tmpr;
	struct cachefile_array array = { 0 };

	array.capacity = 4;
	array.files = pcalloc(array.capacity, sizeof(struct cache_file *));

	HASH_ITER(hh, ctx->fbs.ht, fb, tmpf)
		for (; fb; fb = fb->next)
			HASH_ITER(hh, fb->files.ht, ref, tmpr)
				if (strcmp(ref->file->map.path, path) == 0) {
					if (array.count == array.capacity) {
						array.capacity <<= 1;
						array.files = prealloc(
						    array.files,
						    array.capacity * sizeof(
						        struct cache_file *
						    )
						);
					}
					array.files[array.count++] = ref->file;
				}

	return array;
}

static void
cachefile_set_path(struct cache_file *file, char *path, size_t id_offset)
{
	free(file->map.path);
	file->map.path = path;
	file->id = path + id_offset;
}

static char *
sed_state(char const *path, char const *old, char const *new)
{
	char *result;
	char *slash;

	result = pstrdup(path);

	slash = strchr(path, '/');
	if (!slash)
		pr_panic("Path lacks a first slash: %s", path);
	slash = strchr(slash + 1, '/');
	if (!slash)
		pr_panic("Path lacks a second slash: %s", path);
	if (strncmp(slash + 1, old, 3) != 0)
		pr_panic("Old path lacks '%s' component: %s", old, path);

	slash[1] = new[0];
	slash[2] = new[1];
	slash[3] = new[2];
	return result;
}

static int
commit(struct rsync_ctx *ctx, struct cache_file_ref *new)
{
	char *src_path;
	char *dst_path;
	char *newpath;
	struct cachefile_array fbs;
	array_index f;
	char const *id;
	int error;

	src_path = new->file->map.path;
	dst_path = sed_state(src_path, "new", "rmt");

	if (file_isreg(dst_path)) {
		fbs = find_fallbacks(ctx, dst_path);
		if (fbs.count != 0) {
			newpath = cseq_next(&ctx->fbseq, &id);
			if (!newpath) {
				free(fbs.files);
				error = EINVAL;
				goto cancel;
			}

			error = file_mv(dst_path, newpath);
			if (error) {
				free(newpath);
				free(fbs.files);
				goto cancel;
			}

			cachefile_set_path(fbs.files[0], newpath, 0);
			for (f = 1; f < fbs.count; f++)
				if (fbs.files[f]->map.path != newpath)
					cachefile_set_path(fbs.files[f],
					    pstrdup(newpath), 0);
		}
		free(fbs.files);

	} else {
		/* TODO (performance) Too many mkdir()s */
		error = mkdir_p(dst_path, strlen(ctx->remote_path) + 1);
		if (error)
			goto cancel;
	}

	error = file_mv(src_path, dst_path);
	if (error)
		goto cancel;

	filerefs_rm(&ctx->new, new);

	free(new->file->map.path);
	new->file->map.path = dst_path;
	new->file->id = dst_path;

	filerefs_replace_uri(&ctx->remote, new, 0, false);

	return 0;

cancel:	free(dst_path);
	return error;
}

bool
rsync_cleanup(struct rsync_ctx *ctx)
{
	struct cache_file_ref *new, *tmpn;

	/* 1. Delete noncommitted fallbacks */
	fallbacks_cleanup(&ctx->fbs);

	/* 2. Move all the new/ files to rmt/ */
	if (HASH_COUNT(ctx->new.ht) != 0) {
		HASH_ITER(hh, ctx->new.ht, new, tmpn)
			if (commit(ctx, new) != 0)
				return false;
		file_rm_rf(ctx->new_path);
	}

	/* 3. Delete old unused rmt/ files */
	/* XXX */

	return true;
}

void
rsync_free(struct rsync_ctx *ctx)
{
	free(ctx->remote_path);
	free(ctx->new_path);
	free(ctx->fb_path);

	filerefs_clear(&ctx->remote, false);
	filerefs_clear(&ctx->new, false);
	cseq_cleanup(&ctx->fbseq);

	fallbacks_clear(&ctx->fbs, false);

	free(ctx);
}

void
rsync_print(struct rsync_ctx *ctx, int indent)
{
	printf("%*s[rsync Context]\n", indent, "");
	printf("%*s[Remote] path:%s\n", indent + 2, "", ctx->remote_path);
	filerefs_print(&ctx->remote, indent + 4);
	printf("%*s[New] path:%s\n", indent + 2, "", ctx->new_path);
	filerefs_print(&ctx->new, indent + 4);
	printf("%*s[Fallback] path:%s\n", indent + 2, "", ctx->fb_path);
	fallbacks_print(&ctx->fbs, indent + 4);
}

json_t *
rsync_ctx2json(struct rsync_ctx *ctx)
{
	json_t *root, *files, *fbs;
	struct cache_file_ref *ref, *tmpr;
	struct cache_file *file;
	struct fallback *fb, *tmp;

	root = json_obj_new();

	if (json_object_add(root, "files", (files = json_obj_new())))
		goto fail;
	if (json_object_add(root, "fallbacks", (fbs = json_obj_new())))
		goto fail;

	/* TODO (performance) Maybe add a linked list */
	HASH_ITER(hh, ctx->fbs.ht, fb, tmp)
		HASH_ITER(hh, fb->files.ht, ref, tmpr)
			ref->file->flags &= ~CFF_WRITTEN;

	HASH_ITER(hh, ctx->fbs.ht, fb, tmp) {
		HASH_ITER(hh, fb->files.ht, ref, tmpr) {
			file = ref->file;
			if (!(file->flags & CFF_WRITTEN)) {
				if (json_object_add(files, file->map.path,
						    cachefile2json(file)))
					goto fail;
				ref->file->flags |= CFF_WRITTEN;
			}
		}
		if (json_object_add(fbs, uri_str(&fb->caRepository),
				    fallback2json(fb)))
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

int
rsync_json2ctx(json_t *json, struct cache_mapping *root,
    struct rsync_ctx **result)
{
	struct rsync_ctx *ctx;
	json_t *child;
	struct files_ht files;
	int error;

	ctx = pzalloc(sizeof(struct rsync_ctx));
	ctx->remote_path = path_join(root->path, "rmt");
	ctx->new_path = path_join(root->path, "new");
	ctx->fb_path = path_join(root->path, "fbk");

	error = json_get_object(json, "files", &child);
	if (error)
		goto strs;
	error = json2files(child, NULL, &files);
	if (error)
		goto strs;
	error = json2cseq(&ctx->fbseq, child, ctx->fb_path, true);
	if (error)
		goto files;

	printf("rsync context from JSON:\n");
	filerefs_print(&files, 2);

	error = json_get_object(json, "fallbacks", &child);
	if (error)
		goto cseq;
	error = json2fallbacks(child, &ctx->fbs, &files);
	if (error)
		goto cseq;

	filerefs_clear(&files, true);
	*result = ctx;
	return 0;

cseq:	cseq_cleanup(&ctx->fbseq);
files:	filerefs_clear(&files, false);
strs:	free(ctx->fb_path);
	free(ctx->new_path);
	free(ctx->remote_path);
	free(ctx);
	return error;
}

struct rsync_dao *
rsyncdao_create(struct rsync_ctx *ctx, struct uri *caRepository)
{
	struct rsync_dao *result = pmalloc(sizeof(struct rsync_dao));

	uri_copy(&result->caRepository, caRepository);
	result->state = RDS_REFRESH;
	result->ctx = ctx;
	result->fb = fallback_find(&ctx->fbs, caRepository);

	return result;
}

struct cache_file *
rsyncdao_map(struct rsync_dao *dao, struct uri const *url)
{
	struct cache_file_ref *ref;

	switch (dao->state) {
	case RDS_REFRESH:
		/* TODO (fine) can be slightly optimized by reusing the hash */
		ref = filerefs_find_uri(&dao->ctx->new, url);
		if (ref)
			return ref->file;
		ref = filerefs_find_uri(&dao->ctx->remote, url);
		if (ref)
			return ref->file;
		break;

	case RDS_FALLBACK:
		ref = filerefs_find_uri(&dao->fb->files, url);
		if (ref)
			return ref->file;
		break;

	case RDS_DONE:
		break;
	}

	return NULL;
}

bool
rsyncdao_downgrade(struct rsync_dao *dao)
{
	if (dao->state == RDS_REFRESH && dao->fb) {
		dao->state = RDS_FALLBACK;
		return true;
	}

	dao->state = RDS_DONE;
	return false;
}

struct mft_meta const *
rsyncdao_fallback_mftnum(struct rsync_dao const *dao)
{
	/* XXX There can be multiple fallbacks (RRDP too apparently) */
	return (dao && dao->fb) ? &dao->fb->mft : NULL;
}

void
rsyncdao_commit(struct rsync_dao *dao, struct rpp *rpp)
{
	pr_trc("Queuing RPP for commit: %s", uri_str(&dao->caRepository));

	switch (dao->state) {
	case RDS_REFRESH:
		/* XXX it might add it multiple times. */
		fallback_add(&dao->ctx->fbs, &dao->caRepository, rpp);
		break;
	case RDS_FALLBACK:
		pr_trc("It's already a fallback.");
		fallback_commit(&dao->ctx->fbs, dao->fb);
		break;
	case RDS_DONE:
		pr_trc("Nothing to commit.");
		break;
	}
}

void
rsyncdao_free(struct rsync_dao *dao)
{
	if (dao) {
		uri_cleanup(&dao->caRepository);
		free(dao);
	}
}
