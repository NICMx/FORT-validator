#include "cachefile.h"

#include "common.h"
#include "file.h"
#include "json_util.h"
#include "log.h"
#include "types/map.h"
#include "types/path.h"
#include "types/rpp.h"

int
json_add_hash(json_t *parent, char const *name, unsigned char const *hash)
{
	char *str;
	int res;

	str = hex2str(hash, SHA256_DIGEST_LENGTH);
	res = json_object_set_new(parent, name, json_string(str));
	free(str);

	return res
	    ? pr_err("Cannot convert %s to json; unknown cause.", name)
	    : 0;
}

int
json2hash(json_t *parent, char const *name, unsigned char const *hash)
{
	char const *str;
	int error;

	error = json_get_str(parent, name, &str);
	if (error)
		return error;

	if (strlen(str) != 2 * SHA256_DIGEST_LENGTH)
		return -pr_err("Hash is not %d characters long.",
		    2 * SHA256_DIGEST_LENGTH);
	if (str2hex(str, (uint8_t *)hash) != 0)
		return -pr_err("Malformed hash: %s", str);

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
	memcpy(result->hash, hash, SHA256_DIGEST_LENGTH);
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

unsigned char const *
cachefile_hash(struct cache_file *file)
{
	return file->hash;
}

bool
cachefile_is_committed(struct cache_file *file)
{
	return file->flags & CFF_COMMITTED;
}

void
cachefile_commit(struct cache_file *file)
{
	file->flags |= CFF_COMMITTED;
}

/* Swallows @newpath */
int
cachefile_move(struct cache_file *file, char *newpath)
{
	int error;

	if (rename(file->map.path, newpath) < 0) {
		error = errno;
		free(newpath);
		return error;
	}

	free(file->map.path);
	file->map.path = newpath;
	return 0;
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

static struct cache_file *
json2cachefile(char const *key, char const *pfx, json_t *json)
{
	struct cache_file *file;

	file = pmalloc(sizeof(struct cache_file));

	if (json_get_uri(json, "uri", &file->map.url))
		goto file;
	if (json2hash(json, "hash", file->hash))
		goto url;
	file->map.path = path_join(pfx, key);
	file->id = file->map.path + (strlen(file->map.path) - strlen(key));
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

struct files_ht
filerefs_clone(struct files_ht *refs)
{
	struct cache_file_ref *src, *dst, *tmp;
	struct files_ht result;
	char const *urlstr;
	size_t urlen;

	result.ht = NULL;

	HASH_ITER(hh, refs->ht, src, tmp) {
		dst = fileref_create(src->file);
		urlstr = uri_str(&dst->file->map.url);
		urlen = uri_len(&dst->file->map.url);
		HASH_ADD_KEYPTR(hh, result.ht, urlstr, urlen, dst);
	}

	return result;
}

void
filerefs_clear(struct files_ht *refs, bool rm_files)
{
	struct cache_file_ref *file, *tmp;

	HASH_ITER(hh, refs->ht, file, tmp) {
		HASH_DEL(refs->ht, file);
		fileref_free(file, rm_files);
	}
}

/* Adds file to the hash table, indexes by URI */
void
filerefs_add_uri(struct files_ht *refs, struct cache_file *file,
    unsigned int addref)
{
	struct cache_file_ref *ref;
	char const *urlstr;
	size_t urlen;

	ref = pzalloc(sizeof(struct cache_file_ref));
	ref->file = file;
	if (addref)
		atomic_fetch_add(&file->refcount, addref);

	urlstr = uri_str(&file->map.url);
	urlen = uri_len(&file->map.url);

	HASH_ADD_KEYPTR(hh, refs->ht, urlstr, urlen, ref);
}

void
filerefs_replace_uri(struct files_ht *refs, struct cache_file_ref *ref,
    unsigned int addref, bool rm_file)
{
	struct cache_file_ref *old;
	char const *urlstr;
	size_t urlen;

	if (addref)
		atomic_fetch_add(&ref->file->refcount, addref);

	urlstr = uri_str(&ref->file->map.url);
	urlen = uri_len(&ref->file->map.url);

	HASH_OVERRIDE_KEYPTR(refs->ht, urlstr, urlen, ref, old);

	if (old)
		fileref_free(old, rm_file);
}

void
filerefs_rm(struct files_ht *refs, struct cache_file_ref *ref)
{
	HASH_DEL(refs->ht, ref);
}

struct cache_file_ref *
filerefs_find_uri(struct files_ht *refs, struct uri const *uri)
{
	char const *str;
	size_t len;
	struct cache_file_ref *file;

	if (!refs)
		return NULL;

	str = uri_str(uri);
	len = uri_len(uri);

	HASH_FIND(hh, refs->ht, str, len, file);

	return file;
}

void
filerefs_clear_written(struct files_ht *refs)
{
	struct cache_file_ref *ref, *tmp;

	HASH_ITER(hh, refs->ht, ref, tmp)
		ref->file->flags &= ~CFF_WRITTEN;
}

int
filerefs_write(json_t *json, struct files_ht *files)
{
	struct cache_file_ref *ref, *tmp;
	struct cache_file *file;

	HASH_ITER(hh, files->ht, ref, tmp) {
		file = ref->file;
		if (!(file->flags & CFF_WRITTEN)) {
			if (json_object_add(json,
			    cachefile_id(file),
			    cachefile2json(file)))
				return EINVAL;
			file->flags |= CFF_WRITTEN;
		}
	}

	return 0;
}

int
json2files(json_t *jfiles, char const *path, struct files_ht *files)
{
	char const *key, *id;
	json_t *jfile;
	struct cache_file_ref *fileref, *old;

	files->ht = NULL;

	json_object_foreach(jfiles, key, jfile) {
		fileref = pzalloc(sizeof(struct cache_file_ref));

		fileref->file = json2cachefile(key, path, jfile);
		if (!fileref->file) {
			free(fileref);
			filerefs_clear(files, true);
			return EINVAL;
		}

		id = fileref->file->id;
		HASH_ADD_KEYSTR_SAFE(files->ht, id, fileref, old);
		if (old) {
			pr_err("Duplicate ID in JSON file list: %s", id);
			fileref_free(fileref, true);
			filerefs_clear(files, true);
			return EEXIST;
		}
	}

	return 0;
}

json_t *
filerefs2json(struct files_ht *refs, enum files_key_type kt)
{
	json_t *jfiles;
	struct cache_file_ref *fileref, *tmp;
	char const *key;

	jfiles = json_array_new();

	HASH_ITER(hh, refs->ht, fileref, tmp) {
		switch (kt) {
		case FHKT_ID:	key = fileref->file->id;	break;
		case FHKT_PATH: key = fileref->file->map.path;	break;
		default:	pr_panic("Unknown key type: %u", kt);
		}

		if (json_array_add(jfiles, json_str_new(key))) {
			json_decref(jfiles);
			return NULL;
		}
	}

	return jfiles;
}

static struct cache_file_ref *
find_file(struct files_ht *ht, char const *key)
{
	size_t keylen;
	struct cache_file_ref *file;

	keylen = strlen(key);
	HASH_FIND(hh, ht->ht, key, keylen, file);

	return file;
}

int
json2filerefs(json_t *parent, char const *name, struct files_ht *src_ht,
    struct files_ht *result)
{
	struct cache_file_ref *src, *dst, *old;
	json_t *jfrs, *jfr;
	size_t f;
	char const *key;
	size_t keylen;
	int error;

	result->ht = NULL;

	error = json_get_array(parent, name, &jfrs);
	if (error)
		return error;

	json_array_foreach(jfrs, f, jfr) {
		if (!json_is_string(jfr)) {
			error = -pr_err("File path identifier is not a string.");
			goto oops;
		}

		key = json_string_value(jfr);
		src = find_file(src_ht, key);
		if (!src) {
			error = -pr_err("'%s' is not a defined file.", key);
			goto oops;
		}

		dst = fileref_create(src->file);
		key = uri_str(&dst->file->map.url);
		keylen = uri_len(&dst->file->map.url);
		HASH_ADD_KEYPTR_SAFE(result->ht, key, keylen, dst, old);
		if (old) {
			pr_wrn("File '%s' is listed more than once.",
			    dst->file->map.path);
			fileref_free(dst, false);
		}
	}

	return 0;

oops:	filerefs_clear(result, true);
	return error;
}

void
filerefs_print(struct files_ht *refs, int indent)
{
	struct cache_file_ref *ref, *tmp;

	HASH_ITER(hh, refs->ht, ref, tmp)
		fileref_print(ref, indent);
}

void
fileref_print(struct cache_file_ref *ref, int indent)
{
	printf("%*s[File] id:%s refs:%u fileptr:%p uri:%s path:%s\n",
	    indent, "",
	    ref->file->id,
	    atomic_fetch_add(&ref->file->refcount, 0),
	    (void *) ref->file,
	    uri_str(&ref->file->map.url),
	    ref->file->map.path);
}

json_t *
mft2json(struct mft_meta *mft)
{
	json_t *jmft = json_obj_new();

	if (json_add_str(jmft, "file", mft->file->id))
		goto fail;
	if (json_add_bigint(jmft, "number", &mft->num))
		goto fail;
	if (json_add_ts(jmft, "update", mft->update))
		goto fail;

	return jmft;

fail:	json_decref(jmft);
	return NULL;
}

struct fallback *
fallback_find(struct fallback_ht *fbs, struct uri const *caRepo)
{
	char const *key;
	size_t kl;
	struct fallback *result;

	key = uri_str(caRepo);
	kl = uri_len(caRepo);
	HASH_FIND(hh, fbs->ht, key, kl, result);

	return result;
}

/* Steals @rpp's files. */
/* TODO (fine) why does rpp not contain caRepo? */
void
fallback_add(struct fallback_ht *fbs, struct uri *caRepo, struct rpp *rpp)
{
	struct fallback *fb, *old;
	array_index i;
	char const *key;
	size_t keylen;

	fb = pzalloc(sizeof(struct fallback));
	uri_copy(&fb->caRepository, caRepo);
	for (i = 0; i < rpp->nfiles; i++)
		filerefs_add_uri(&fb->files, rpp->files[i], 1);
	fb->mft = rpp->mft;
	memset(&rpp->mft, 0, sizeof(rpp->mft));
	fb->committed = true;

	key = uri_str(&fb->caRepository);
	keylen = uri_len(&fb->caRepository);

	mutex_lock(&fbs->lock);
	HASH_ADD_KEYPTR_SAFE(fbs->ht, key, keylen, fb, old);
	if (old) {
		fb->next = old->next;
		old->next = fb;
	}
	mutex_unlock(&fbs->lock);

	free(rpp->files);
	rpp->files = NULL;
	rpp->nfiles = 0;
}

void
fallback_commit(struct fallback_ht *ht, struct fallback *fb)
{
	mutex_lock(&ht->lock);
	fb->committed = true;
	mutex_unlock(&ht->lock);
}

/* Notice the result */
static struct fallback *
fallback_free(struct fallback *fb, bool rm_files)
{
	struct fallback *next = fb->next;

	uri_cleanup(&fb->caRepository);
	filerefs_clear(&fb->files, rm_files);
	mftm_cleanup(&fb->mft);
	free(fb);

	return next;
}

/* Notice the plural. */
void
fallbacks_free(struct fallback *fb, bool rm_files)
{
	while (fb)
		fb = fallback_free(fb, rm_files);
}

void
fallbacks_clear(struct fallback_ht *fbs, bool rm_files)
{
	struct fallback *fb, *tmp;

	HASH_ITER(hh, fbs->ht, fb, tmp) {
		HASH_DEL(fbs->ht, fb);
		fallbacks_free(fb, rm_files);
	}
}

void
fallbacks_cleanup(struct fallback_ht *fbs)
{
	struct fallback *first, *cursor, *newest, *tmpf;

	HASH_ITER(hh, fbs->ht, first, tmpf) {
		newest = NULL;
		for (cursor = first; cursor; cursor = cursor->next)
			if (cursor->committed)
				if (!newest || INTEGER_cmp(&cursor->mft.num, &newest->mft.num) > 0)
					newest = cursor;

		if (!newest) {
			HASH_DEL(fbs->ht, first);
			fallbacks_free(first, true);
			continue;
		}

		if (first != newest) {
			filerefs_clear(&first->files, true);
			first->files = newest->files;
			memset(&newest->files, 0, sizeof(newest->files));

			mftm_cleanup(&first->mft);
			first->mft = newest->mft;
			memset(&newest->mft, 0, sizeof(newest->mft));

			first->committed = true;
		}

		fallbacks_free(first->next, true);
		first->next = NULL;
	}
}

static void
fallback_print(struct fallback *fb, int indent)
{
	struct cache_file_ref *ref, *tmp;
	char *mftnum;

	printf("%*s[Fallback] caRepository:%s ", indent, "",
	    uri_str(&fb->caRepository));
	mftnum = asn_INTEGER2str(&fb->mft.num);
	printf("mftnum:%s ", mftnum);
	free(mftnum);
	printf("committed:%u\n", fb->committed);

	HASH_ITER(hh, fb->files.ht, ref, tmp)
		fileref_print(ref, indent + 2);
}

void
fallbacks_print(struct fallback_ht *fbs, int indent)
{
	struct fallback *fb, *tmp2;

	HASH_ITER(hh, fbs->ht, fb, tmp2)
		for (; fb; fb = fb->next)
			fallback_print(fb, indent);
}

json_t *
fallback2json(struct fallback *fb, enum files_key_type kt)
{
	json_t *json;

	json = json_obj_new();

	if (json_object_add(json, "files", filerefs2json(&fb->files, kt)))
		goto fail;
	if (json_object_add(json, "manifest", mft2json(&fb->mft)))
		goto fail;

	return json;

fail:	json_decref(json);
	return NULL;
}

static int
load_mft_file(json_t *jmft, struct files_ht *refs, struct cache_file **result)
{
	char const *str;
	struct cache_file_ref *ref;
	int error;

	error = json_get_str(jmft, "file", &str);
	if (error)
		return error;

	ref = find_file(refs, str);
	if (!ref)
		return -pr_err("Manifest file is not declared: %s", str);

	*result = ref->file;
	return 0;
}

int
json2fallback(json_t *json, char const *key, struct files_ht *refs,
    struct fallback **result)
{
	json_t *jmft;
	struct fallback *fb;
	error_msg errmsg;
	int error;

	*result = NULL;
	fb = pzalloc(sizeof(struct fallback));

	errmsg = uri_init(&fb->caRepository, key);
	if (errmsg) {
		error = pr_err("Bad URL: %s", errmsg);
		goto fb;
	}

	error = json2filerefs(json, "files", refs, &fb->files);
	if (error)
		goto uri;

	error = json_get_object(json, "manifest", &jmft);
	if (error)
		goto refs;
	error = load_mft_file(jmft, refs, &fb->mft.file);
	if (error)
		goto refs;
	error = json_get_bigint(jmft, "number", &fb->mft.num);
	if (error)
		goto refs;
	error = json_get_ts(jmft, "update", &fb->mft.update);
	if (error)
		goto mft;

	*result = fb;
	return 0;

mft:	INTEGER_cleanup(&fb->mft.num);
refs:	filerefs_clear(&fb->files, true);
uri:	uri_cleanup(&fb->caRepository);
fb:	free(fb);
	return error;
}

int
json2fallbacks(json_t *jfbs, struct fallback_ht *fbs, struct files_ht *files)
{
	char const *jkey;
	json_t *child;
	struct fallback *fb, *old;
	char const *key;
	size_t keylen;
	int error;

	json_object_foreach(jfbs, jkey, child) {
		error = json2fallback(child, jkey, files, &fb);
		if (error)
			return error;
		key = uri_str(&fb->caRepository);
		keylen = uri_len(&fb->caRepository);
		HASH_ADD_KEYPTR_SAFE(fbs->ht, key, keylen, fb, old);
		if (old)
			return pr_err("Table has multiple fallbacks named '%s'.",
			    key);
	}

	return 0;
}
