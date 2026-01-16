#ifndef SRC_CACHE_LOCAL_CACHE_H_
#define SRC_CACHE_LOCAL_CACHE_H_

#include "common.h"
#include "types/rpp.h"

int cache_setup1(void);
int cache_setup2(void);
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

struct cache_cage;
struct rpp_querier;
struct file_querier;

struct cache_ta {
	struct cache_mapping map;	/* Fallback */
	char *tmppath;			/* Refresh */
};

validation_verdict cache_get_fallback(struct uri const *, struct rpp_querier *);

struct rpp_querier *querier_create(struct extension_uris *);
struct cache_file *querier_map(struct rpp_querier *, struct uri const *);
void querier_get_fallback_mftnums(struct rpp_querier *,
    struct mft_meta const **, struct mft_meta const **);
validation_verdict querier_downgrade(struct rpp_querier *);
void querier_free(struct rpp_querier *);

void cache_commit_rpp(struct rpp_querier *, struct rpp *);

validation_verdict fquery_refresh_https(struct uri const *, struct file_querier **);
validation_verdict fquery_refresh_rsync(struct uri const *, struct file_querier **);
validation_verdict fquery_fallback_https(struct uri const *, struct file_querier **);
validation_verdict fquery_fallback_rsync(struct uri const *, struct file_querier **);
char const *fquerier_map(struct file_querier *);
void fquerier_commit(struct file_querier *);
#define fquerier_free free

void cache_print(void);		/* Dump cache in stdout */

#endif /* SRC_CACHE_LOCAL_CACHE_H_ */
