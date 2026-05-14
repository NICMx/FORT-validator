#ifndef SRC_DAO_RSYNC_H_
#define SRC_DAO_RSYNC_H_

#include <stdbool.h>
#include <jansson.h>
#include "types/rpp.h"

/*
 * TODO maybe rename "ctx" into "repo," and "dao" into "rpp".
 * I keep forgetting that a DAO is locked to a single RPP, yet it's really
 * very important.
 * Honestly, "dao" is also more like a "mapper" than a DAO.
 */

/*
 * Persistent rsync cache node metadata
 * (There's one of these for every rsync repository)
 */
struct rsync_ctx;

/* Rebuild index file; needs to be called after rsync refresh */
int rsync_reindex(struct rsync_ctx **, struct cache_mapping *);
/*
 * Cache directory post-processing (after validation cycle).
 * Mostly deletes files that no longer need to be preserved.
 */
bool rsync_cleanup(struct rsync_ctx *);
/* Delete object from RAM (not cache directory) */
void rsync_free(struct rsync_ctx *);

/* For debugging */
void rsync_print(struct rsync_ctx *, int);

/* Convert metadata to json */
json_t *rsync_ctx2json(struct rsync_ctx *);
/* Convert json to metadata */
int rsync_json2ctx(json_t *, struct cache_mapping *, struct rsync_ctx **);

/*
 * URI to cache path querier, for individual files in a given RPP.
 * At first, it returns refresh paths (if available).
 * After downgrade(), it returns fallback paths (if available).
 * After another downgrade(), it's invalidated.
 */
struct rsync_dao;

/* Get new querier for the given RPP in the given repository */
struct rsync_dao *rsyncdao_create(struct rsync_ctx *, struct uri *);
/* Get local cache path of the file identified by the given URI */
struct cache_file *rsyncdao_map(struct rsync_dao *, struct uri const *);
/* Commands map() to return lesser priority URIs from now on */
bool rsyncdao_downgrade(struct rsync_dao *);
/* Returns the manifest number of the RPP currently being queried */
struct mft_meta const *rsyncdao_fallback_mftnum(struct rsync_dao const *);
/* Mark RPP for preservation (during cleanup) */
void rsyncdao_commit(struct rsync_dao *, struct rpp *);
/* Delete object from RAM (not cache directory) */
void rsyncdao_free(struct rsync_dao *);

#endif /* SRC_DAO_RSYNC_H_ */
