#ifndef SRC_CACHEFILE_H_
#define SRC_CACHEFILE_H_

#include <stdbool.h>
#include <jansson.h>

#include "hash.h"
#include "types/map.h"
#include "types/uthash.h"

int json_add_hash(json_t *, char const *, struct rrdp_hash const *);
int json2hash(json_t *, char const *, struct rrdp_hash *);

struct cache_file;

struct cache_file *cachefile_create(struct uri *, char *, char const *,
    unsigned char *);
void cachefile_refget(struct cache_file *);
void cachefile_refput(struct cache_file *, bool);

struct cache_mapping const *cachefile_map(struct cache_file *);
struct uri const *cachefile_uri(struct cache_file *);
char const *cachefile_id(struct cache_file *);
struct rrdp_hash const *cachefile_hash(struct cache_file *);

bool cachefile_get_written(struct cache_file *);
void cachefile_set_written(struct cache_file *, bool);

json_t *cachefile2json(struct cache_file *);
struct cache_file *json2cachefile(char const *, char const *, json_t *);


struct cache_file_ref {
	struct cache_file *file;
	UT_hash_handle hh;		/* Hash table hook */
};

typedef struct cache_file_ref files_ht;	/* Hash table */

struct cache_file_ref *fileref_create(struct cache_file *);
void fileref_free(struct cache_file_ref *, bool);

files_ht *filerefs_clone(files_ht *);
void filerefs_clear(files_ht *, bool);

void filerefs_add_uri(files_ht **, struct cache_file *, unsigned int);
struct cache_file_ref *filerefs_find_uri(files_ht *, struct uri const *);

json_t *filerefs2json(files_ht *);
int json2filerefs(json_t *, char const *, files_ht *, files_ht **);

void fileref_print(struct cache_file_ref *);

#endif /* SRC_CACHEFILE_H_ */
