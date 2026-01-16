#include "cachefile.h"

#include <stdatomic.h>
#include <stdbool.h>

#include "common.h"
#include "file.h"
#include "json_util.h"
#include "log.h"
#include "types/map.h"
#include "types/path.h"

struct cache_file {
	struct cache_mapping map;
	/*
	 * If map.path is "http/1/456", then id is "456".
	 * id always points to map.path's substring.
	 */
	char const *id;
	struct rrdp_hash hash;
	bool written;
	atomic_uint refcount;
};

int
json_add_hash(json_t *parent, char const *name, struct rrdp_hash const *hash)
{
	char *str;
	int res;

	if (!hash->set)
		return 0;

	str = hex2str(hash->bytes, RRDP_HASH_LEN);
	res = json_object_set_new(parent, name, json_string(str));
	free(str);

	return res
	    ? pr_err("Cannot convert %s to json; unknown cause.", name)
	    : 0;
}

int
json2hash(json_t *parent, char const *name, struct rrdp_hash *hash)
{
	char const *str;
	int error;

	error = json_get_str(parent, name, &str);
	if (error == ENOENT) {
		hash->set = false;
		return 0;
	}
	if (error)
		return error;

	if (strlen(str) != 2 * RRDP_HASH_LEN)
		return -pr_err("Hash is not %d characters long.", 2 * RRDP_HASH_LEN);
	if (str2hex(str, hash->bytes) != 0)
		return -pr_err("Malformed hash: %s", str);

	hash->set = true;
	return 0;
}

struct cache_file *
cachefile_create(struct uri *url, char *path, char const *id,
    unsigned char *hash)
{
	struct cache_file *result;

	result = pmalloc(sizeof(struct cache_file));
	uri_copy(&result->map.url, url);
	result->map.path = path;
	result->id = id;
	if (hash) {
		memcpy(result->hash.bytes, hash, RRDP_HASH_LEN);
		result->hash.set = true;
	} else {
		result->hash.set = false;
	}
	atomic_init(&result->refcount, 1);

	return result;
}

void
cachefile_refget(struct cache_file *file)
{
	atomic_fetch_add(&file->refcount, 1);
}

void
cachefile_refput(struct cache_file *file, bool rm)
{
	if (atomic_fetch_sub(&file->refcount, 1) <= 1) {
		if (rm)
			file_rm_f(file->map.path);
		map_cleanup(&file->map);
		free(file);
	}
}

struct cache_mapping const *
cachefile_map(struct cache_file *file)
{
	return &file->map;
}

struct uri const *
cachefile_uri(struct cache_file *file)
{
	return &file->map.url;
}

char const *
cachefile_id(struct cache_file *file)
{
	return file->id;
}

struct rrdp_hash const *
cachefile_hash(struct cache_file *file)
{
	return &file->hash;
}

bool
cachefile_get_written(struct cache_file *file)
{
	return file->written;
}

void
cachefile_set_written(struct cache_file *file, bool written)
{
	file->written = written;
}

json_t *
cachefile2json(struct cache_file *file)
{
	json_t *jfile;

	jfile = json_obj_new();

	if (json_add_str(jfile, "uri", uri_str(cachefile_uri(file))))
		goto fail;
	if (json_add_hash(jfile, "hash", cachefile_hash(file)))
		goto fail;

	return jfile;

fail:	json_decref(jfile);
	return NULL;
}

struct cache_file *
json2cachefile(char const *key, char const *pfx, json_t *json)
{
	struct cache_file *file;

	file = pmalloc(sizeof(struct cache_file));

	if (json_get_uri(json, "uri", &file->map.url))
		goto file;
	if (json2hash(json, "hash", &file->hash) < 0)
		goto url;
	file->map.path = path_join(pfx, key);
	file->id = strrchr(file->map.path, '/');
	file->id = (file->id) ? (file->id + 1) : file->map.path;
	file->refcount = 1;

	return file;

url:	uri_cleanup(&file->map.url);
file:	free(file);
	return NULL;
}

struct cache_file_ref *
fileref_create(struct cache_file *file)
{
	struct cache_file_ref *result;

	result = pzalloc(sizeof(struct cache_file_ref));
	result->file = file;
	cachefile_refget(file);

	return result;
}

void
fileref_free(struct cache_file_ref *file, bool rm_file)
{
	cachefile_refput(file->file, rm_file);
	free(file);
}

files_ht *
filerefs_clone(files_ht *files)
{
	struct cache_file_ref *src, *dst, *tmp;
	struct cache_file_ref *result;
	char const *urlstr;
	size_t urlen;

	result = NULL;

	HASH_ITER(hh, files, src, tmp) {
		dst = fileref_create(src->file);
		urlstr = uri_str(&dst->file->map.url);
		urlen = uri_len(&dst->file->map.url);
		HASH_ADD_KEYPTR(hh, result, urlstr, urlen, dst);
	}

	return result;
}

void
filerefs_clear(files_ht *ht, bool rm_files)
{
	struct cache_file_ref *file, *tmp;

	HASH_ITER(hh, ht, file, tmp) {
		HASH_DEL(ht, file);
		fileref_free(file, rm_files);
	}
}

/* Adds file to the hash table, indexes by URI */
void
filerefs_add_uri(files_ht **ht, struct cache_file *file, unsigned int addref)
{
	char const *urlstr;
	size_t urlen;
	struct cache_file_ref *ref;
	files_ht *_ht;

	urlstr = uri_str(&file->map.url);
	urlen = uri_len(&file->map.url);

	ref = pzalloc(sizeof(struct cache_file_ref));
	ref->file = file;
	if (addref)
		atomic_fetch_add(&file->refcount, addref);

	_ht = *ht;
	HASH_ADD_KEYPTR(hh, _ht, urlstr, urlen, ref);
	*ht = _ht;
}

struct cache_file_ref *
filerefs_find_uri(files_ht *ht, struct uri const *uri)
{
	char const *str;
	size_t len;
	struct cache_file_ref *file;

	str = uri_str(uri);
	len = uri_len(uri);

	HASH_FIND(hh, ht, str, len, file);

	return file;
}

json_t *
filerefs2json(files_ht *ht)
{
	json_t *jfiles, *jkey;
	struct cache_file_ref *fileref, *tmp;

	jfiles = json_array_new();

	HASH_ITER(hh, ht, fileref, tmp) {
		jkey = json_str_new(cachefile_id(fileref->file));
		if (json_array_add(jfiles, jkey)) {
			json_decref(jfiles);
			return NULL;
		}
	}

	return jfiles;
}

int
json2filerefs(json_t *parent, char const *name, files_ht *src_ht,
    files_ht **result)
{
	struct cache_file_ref *src, *dst_ht, *dst, *old;
	json_t *jfrs, *jfr;
	size_t f;
	char const *key;
	size_t keylen;
	int error;

	error = json_get_array(parent, name, &jfrs);
	if (error) {
		*result = NULL;
		return error;
	}

	dst_ht = NULL;

	json_array_foreach(jfrs, f, jfr) {
		if (!json_is_string(jfr)) {
			error = -pr_err("File path identifier is not a string.");
			goto oops;
		}

		key = json_string_value(jfr);
		keylen = strlen(key);
		HASH_FIND(hh, src_ht, key, keylen, src);
		if (!src) {
			error = -pr_err("'%s' is not a defined file.", key);
			goto oops;
		}

		dst = fileref_create(src->file);
		key = uri_str(&dst->file->map.url);
		keylen = uri_len(&dst->file->map.url);
		HASH_ADD_KEYPTR_SAFE(dst_ht, key, keylen, dst, old);
		if (old) {
			pr_wrn("File '%s' is listed more than once.",
			    dst->file->map.path);
			fileref_free(dst, false);
		}
	}

	*result = dst_ht;
	return 0;

oops:	filerefs_clear(dst_ht, true);
	return error;
}

void
fileref_print(struct cache_file_ref *ref)
{
	printf("%s (%u, %p): %s -> %s\n",
	    ref->file->id,
	    atomic_fetch_add(&ref->file->refcount, 0),
	    (void *) ref->file,
	    uri_str(&ref->file->map.url),
	    ref->file->map.path);
}
