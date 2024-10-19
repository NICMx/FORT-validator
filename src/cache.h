#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include <stdbool.h>
#include "types/map.h"
#include "types/rpp.h"

int cache_setup(void);		/* Init this module */
void cache_atexit(void);

int cache_prepare(void);	/* Prepare cache for new validation cycle */
void cache_commit(void);	/* Finish validation cycle */

/* XXX might wanna rename */
struct sia_uris {
	char *caRepository;	/* RPP cage */
	char *rpkiNotify;	/* RRDP Notification */
	char *rpkiManifest;

	/**
	 * CRL Distribution Points's fullName. Non-TA certificates only.
	 * RFC 6487, section 4.8.6.
	 */
	char *crldp;
	/**
	 * AIA's caIssuers. Non-TA certificates only.
	 * RFC 6487, section 4.8.7.
	 */
	char *caIssuers;
	/**
	 * SIA's signedObject. EE certificates only.
	 * RFC 6487, section 4.8.8.2.
	 */
	char *signedObject;
};

void sias_init(struct sia_uris *);
void sias_cleanup(struct sia_uris *);

char *cache_refresh_url(char const *);
char *cache_fallback_url(char const *);

struct cache_cage;
struct cache_cage *cache_refresh_sias(struct sia_uris *);
char const *cage_map_file(struct cache_cage *, char const *);
bool cage_disable_refresh(struct cache_cage *);
void cache_commit_rpp(char const *, struct rpp *);
void cache_commit_file(struct cache_mapping *);

void cache_print(void);		/* Dump cache in stdout */

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
