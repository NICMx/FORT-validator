#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include "types/map.h"

int cache_setup(void);		/* Init this module */
void cache_teardown(void);	/* Destroy this module */

void cache_prepare(void);	/* Prepare cache for new validation cycle */
void cache_commit(void);	/* Finish validation cycle */

struct sia_uris {
	char *caRepository;	/* RPP cage */
	char *rpkiNotify;	/* RRDP Notification */
	char *rpkiManifest;
};

void sias_init(struct sia_uris *);
void sias_cleanup(struct sia_uris *);

int cache_refresh_url(char *, struct cache_mapping *);
int cache_fallback_url(char *, struct cache_mapping *);
int cache_refresh_sias(struct sia_uris *, struct cache_mapping *);

void cache_print(void); /* Dump cache in stdout. Recursive; tests only */

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
