#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include "cache/cachent.h"
#include "types/str.h"

void cache_setup(void);		/* Init this module */
void cache_teardown(void);	/* Destroy this module */

int cache_tmpfile(char **);	/* Return new unique path in <cache>/tmp/ */

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
 *
 * XXX rename
 */
typedef int (*maps_dl_cb)(struct cache_node *rpp, void *arg);
int cache_download_uri(struct strlist *, maps_dl_cb, void *);
int cache_download_alt(struct sia_uris *, maps_dl_cb, void *);

void cache_print(void); /* Dump cache in stdout. Recursive; tests only */

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
