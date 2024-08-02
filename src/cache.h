#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include "types/map.h"
#include "types/str.h"

void cache_setup(void);		/* Init this module */
void cache_teardown(void);	/* Destroy this module */

void cache_prepare(void);	/* Prepare cache for new validation cycle */
void cache_commit(void);	/* Finish successful validation cycle */
/* XXX Huh. Looks like this could use a cache_rollback() */

struct sia_uris {
	char *caRepository;	/* RPP cage */
	char *rpkiNotify;	/* RRDP Notification */
	char *rpkiManifest;
};

void sias_init(struct sia_uris *);
void sias_cleanup(struct sia_uris *);

/*
 * The callback should return
 *
 * - 0 on success ("Mapping handled successfully")
 * - > 0 on soft errors ("Try another mapping")
 * - < 0 on hard errors ("Abandon foreach")
 */
typedef int (*validate_cb)(struct cache_mapping *, void *);
int cache_download_uri(struct strlist *, validate_cb, void *);
int cache_download_alt(struct sia_uris *, validate_cb, void *);

void cache_print(void); /* Dump cache in stdout. Recursive; tests only */

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
