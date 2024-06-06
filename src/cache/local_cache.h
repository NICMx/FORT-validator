#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include "types/map.h"

struct rpki_cache;

void cache_setup(void);
void cache_teardown(void);

int cache_tmpfile(char **);

struct rpki_cache *cache_create(void);
/* Will destroy the cache object, but not the cache directory itself, obv. */
void cache_destroy(struct rpki_cache *);

struct cachefile_notification; /* FIXME */

/* Downloads @map into the cache */
int cache_download(struct rpki_cache *, struct cache_mapping *map, bool *,
    struct cachefile_notification ***);

/*
 * The callback should return
 *
 * - 0 on success ("Mapping handled successfully")
 * - > 0 on soft errors ("Try another mapping")
 * - < 0 on hard errors ("Abandon foreach")
 */
typedef int (*maps_dl_cb)(struct cache_mapping *, void *);
int cache_download_alt(struct rpki_cache *, struct map_list *, enum map_type,
    enum map_type, maps_dl_cb, void *);

/* Returns the most recent successfully cached mapping of the list */
struct cache_mapping *cache_recover(struct rpki_cache *, struct map_list *);
/* Prints the cache in standard output. */
void cache_print(struct rpki_cache *);

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
