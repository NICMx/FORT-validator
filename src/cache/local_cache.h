#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include <curl/curl.h>
#include "types/uri.h"

struct rpki_cache;

void cache_setup(void);
void cache_teardown(void);

int cache_tmpfile(char **);

struct rpki_cache *cache_create(char const *);
/* Will destroy the cache object, but not the cache directory itself, obv. */
void cache_destroy(struct rpki_cache *);

/* Downloads @uri into the cache */
int cache_download(struct rpki_cache *, struct rpki_uri *uri, curl_off_t, bool *);

/*
 * The callback should return
 *
 * - 0 on success ("URI handled successfully")
 * - > 0 on soft errors ("Try another URI")
 * - < 0 on hard errors ("Abandon foreach")
 */
typedef int (*uris_dl_cb)(struct rpki_uri *, void *);
int cache_download_alt(struct rpki_cache *, struct uri_list *, enum uri_type,
    enum uri_type, uris_dl_cb, void *);

/* Returns the most recent successfully cached URI of the list */
struct rpki_uri *cache_recover(struct rpki_cache *, struct uri_list *);
/* Prints the cache in standard output. */
void cache_print(struct rpki_cache *);

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
