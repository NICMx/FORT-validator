#ifndef SRC_RRDP_H_
#define SRC_RRDP_H_

#include <jansson.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "types/rpp.h"
#include "types/uri.h"

struct rrdp_ctx;

int rrdp_update(struct uri const *, char const *, time_t, bool *,
    struct rrdp_ctx **);
void rrdpctx_print(struct rrdp_ctx *, int);
bool rrdpctx_cleanup(struct rrdp_ctx *);
void rrdpctx_free(struct rrdp_ctx *);

json_t *rrdp_ctx2json(struct rrdp_ctx const *);
int rrdp_json2ctx(json_t *, char *, struct rrdp_ctx **);

struct rrdp_dao;

struct rrdp_dao *rrdpdao_create(struct rrdp_ctx *, struct uri const *);
bool rrdpdao_downgrade_delta(struct rrdp_dao *);
bool rrdpdao_downgrade_fb(struct rrdp_dao *);
struct cache_file *rrdpdao_map(struct rrdp_dao const *, struct uri const *);
struct mft_meta const *rrdpdao_fallback_mftnum(struct rrdp_dao *);
void rrdpdao_commit(struct rrdp_dao *, struct rpp *);
void rrdpdao_free(struct rrdp_dao *);

#endif /* SRC_RRDP_H_ */
