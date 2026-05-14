#ifndef SRC_CACHEFILE_H_
#define SRC_CACHEFILE_H_

#include <stdatomic.h>
#include <stdbool.h>
#include <jansson.h>

#include "asn1/asn1c/INTEGER.h"
#include "hash.h"
#include "types/map.h"
#include "types/uthash.h"

int json_add_hash(json_t *, char const *, struct rrdp_hash const *);
int json2hash(json_t *, char const *, struct rrdp_hash *);

#define CFF_WRITTEN	(1 << 0)
#define CFF_COMMITTED	(1 << 1)

struct cache_file {
	struct cache_mapping map;
	/*
	 * If map.path is "http/1/456", then id is "456".
	 * id always points to map.path's substring.
	 */
	char const *id;
	/* XXX not RRDP only anymore */
	struct rrdp_hash hash;
	int flags;
	atomic_uint refcount;
};

struct cache_file *cachefile_create(struct uri *, char *, char const *,
    unsigned char *);
void cachefile_refget(struct cache_file *);
void cachefile_refput(struct cache_file *, bool);

bool cachefile_is_committed(struct cache_file *);
void cachefile_commit(struct cache_file *);

int cachefile_move(struct cache_file *, char *);

struct cache_file_ref {
	struct cache_file *file;
	UT_hash_handle hh;		/* Hash table hook */
};

struct files_ht {
	struct cache_file_ref *ht;
};

struct cache_file_ref *fileref_create(struct cache_file *);
void fileref_free(struct cache_file_ref *, bool);

struct files_ht filerefs_clone(struct files_ht *);
void filerefs_clear(struct files_ht *, bool);

void filerefs_add_uri(struct files_ht *, struct cache_file *, unsigned int);
void filerefs_replace_uri(struct files_ht *, struct cache_file_ref *, unsigned int, bool);
void filerefs_rm(struct files_ht *, struct cache_file_ref *);
struct cache_file_ref *filerefs_find_uri(struct files_ht *, struct uri const *);

void filerefs_clear_written(struct files_ht *);
int filerefs_write(json_t *, struct files_ht *);

enum files_key_type {
	FHKT_ID,
	FHKT_PATH,
};

int json2files(json_t *, char const *, struct files_ht *);

json_t *filerefs2json(struct files_ht *, enum files_key_type);
int json2filerefs(json_t *, char const *, struct files_ht *, struct files_ht *);

void filerefs_print(struct files_ht *, int);
void fileref_print(struct cache_file_ref *, int);

struct mft_meta {
	INTEGER_t num;				/* Manifest's manifestNumber */
	time_t update;				/* Manifest's thisUpdate */
};

json_t *mft2json(struct mft_meta *);

struct fallback {
	struct uri caRepository;
	struct files_ht files;
	struct mft_meta mft;

	bool committed;			/* Freshly committed? */

	UT_hash_handle hh;
	struct fallback *next;		/* Fallbacks that share caRepository */
};

struct fallback_ht {
	struct fallback *ht;
	pthread_mutex_t lock;
};

struct fallback *fallback_find(struct fallback_ht *, struct uri *);

struct rpp;
void fallback_add(struct fallback_ht *, struct uri *, struct rpp *);
void fallback_commit(struct fallback_ht *, struct fallback *);
void fallbacks_free(struct fallback *, bool);
void fallbacks_clear(struct fallback_ht *, bool);
void fallbacks_cleanup(struct fallback_ht *);
void fallbacks_print(struct fallback_ht *, int);

json_t *fallback2json(struct fallback *, enum files_key_type);
int json2fallback(json_t *, char const *, struct files_ht *, struct fallback **);
int json2fallbacks(json_t *, struct fallback_ht *, struct files_ht *);

#endif /* SRC_CACHEFILE_H_ */
