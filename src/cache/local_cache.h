#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include "types/uri.h"

/* Warms up cache for new validation run */
int cache_prepare(void); /* No revert needed */

/* Downloads @uri into the cache */
int cache_download(struct rpki_uri *uri, bool *);
/* Returns the most recent successfully cached URI of the list */
struct rpki_uri *cache_recover(struct uri_list *, bool);
/* Prints the cache in standard output. */
void cache_print(void);

/* Deletes old untraversed cached files, writes metadata into XML */
/* FIXME call this */
void cache_cleanup(void);

void cache_teardown(void); /* No setup needed */

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
