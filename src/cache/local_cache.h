#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include "types/map.h"
#include "types/str.h"
#include "cache/cachent.h"

struct rpki_cache;
struct cache_node;

void cache_setup(void);
void cache_teardown(void);

int cache_tmpfile(char **);

struct rpki_cache *cache_create(void);
/* Will destroy the cache object, but not the cache directory itself, obv. */
void cache_destroy(void);

struct sia_uris {
	struct strlist caRepository; /* rsync RPPs */
	struct strlist rpkiNotify; /* RRDP Notifications */
	char *rpkiManifest;
};

/*
 * The callback should return
 *
 * - 0 on success ("Mapping handled successfully")
 * - > 0 on soft errors ("Try another mapping")
 * - < 0 on hard errors ("Abandon foreach")
 *
 * XXX rename
 */
typedef int (*maps_dl_cb)(struct cache_node *, void *);
int cache_download_alt(struct sia_uris *, maps_dl_cb, void *);

/* Prints the cache in standard output. */
void cache_print(struct rpki_cache *);

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
