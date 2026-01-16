#ifndef SRC_DAO_RSYNC_H_
#define SRC_DAO_RSYNC_H_

#include <stdbool.h>
#include "types/rpp.h"
#include "types/uri.h"

struct rsync_ctx;
struct rsync_dao;

bool rsync_cleanup(struct rsync_ctx *);

struct rsync_dao *rsyncdao_create(struct rsync_ctx *);
bool rsyncdao_downgrade(struct rsync_dao *);
struct cache_file *rsyncdao_map(struct rsync_dao *, struct uri const *);
struct mft_meta const *rsyncdao_fallback_mftnum(struct rsync_dao const *);
void rsyncdao_commit(struct rsync_dao *, struct rpp *);
void rsyncdao_free(struct rsync_dao *);

#endif /* SRC_DAO_RSYNC_H_ */
