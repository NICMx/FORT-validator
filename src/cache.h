#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include <stdbool.h>
#include "common.h"
#include "types/map.h"
#include "types/rpp.h"
#include "types/uri.h"

int cache_setup(void);		/* Init this module */
void cache_atexit(void);

int cache_prepare(void);	/* Prepare cache for new validation cycle */
void cache_commit(void);	/* Finish validation cycle */

struct extension_uris {
	struct uri caRepository;	/* RPP cage */
	struct uri rpkiNotify;		/* RRDP Notification */
	struct uri rpkiManifest;

	/**
	 * CRL Distribution Points's fullName. Non-TA certificates only.
	 * RFC 6487, section 4.8.6.
	 */
	struct uri crldp;
	/**
	 * AIA's caIssuers. Non-TA certificates only.
	 * RFC 6487, section 4.8.7.
	 */
	struct uri caIssuers;
	/**
	 * SIA's signedObject. EE certificates only.
	 * RFC 6487, section 4.8.8.2.
	 */
	struct uri signedObject;
};

void exturis_init(struct extension_uris *);
void exturis_cleanup(struct extension_uris *);

validation_verdict cache_refresh_by_url(struct uri const *, char const **);
validation_verdict cache_get_fallback(struct uri const *, char const **);

struct cache_cage;
validation_verdict cache_refresh_by_uris(struct extension_uris *,
    struct cache_cage **);
char *cage_map_file(struct cache_cage *, struct uri const *);
bool cage_downgrade(struct cache_cage *);
struct mft_meta const *cage_mft_fallback(struct cache_cage *);
void cache_commit_rpp(struct uri const *, struct uri const *, struct rpp *);
void cache_commit_file(struct cache_mapping const *);

struct uri const *cage_rpkiNotify(struct cache_cage *);

void cache_print(void);		/* Dump cache in stdout */

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
