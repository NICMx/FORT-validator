#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include "types/uri.h"

/* Warms up cache for new validation run */
int cache_prepare(void);

/* Downloads @uri into the cache */
int cache_download(struct rpki_uri *uri, bool *);

/* Deletes old untraversed cached files, writes metadata into XML */
/* FIXME call this */
void cache_cleanup(void);

void cache_teardown(void);

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
