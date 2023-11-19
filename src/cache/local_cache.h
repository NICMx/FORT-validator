#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include "types/uri.h"

struct rpki_cache;

struct rpki_cache *cache_create(char const *);
/* Will destroy the cache object, but not the cache directory itself, obv. */
void cache_destroy(struct rpki_cache *);

/* Downloads @uri into the cache */
int cache_download(struct rpki_cache *, struct rpki_uri *uri, bool *);

/*
 * The callback should return
 *
 * - 0 on success ("URI handled successfully")
 * - > 0 on soft errors ("Try another URI")
 * - < 0 on hard errors ("Abandon foreach")
 */
typedef int (*uris_dl_cb)(struct rpki_uri *, void *);
int cache_download_alt(struct rpki_cache *, struct uri_list *, bool,
    uris_dl_cb, void *);

/* Returns the most recent successfully cached URI of the list */
struct rpki_uri *cache_recover(struct rpki_cache *, struct uri_list *, bool);
/* Prints the cache in standard output. */
void cache_print(struct rpki_cache *);

/* Deletes old untraversed cached files, writes metadata into XML */
/* FIXME call this */
void cache_cleanup(struct rpki_cache *);

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
