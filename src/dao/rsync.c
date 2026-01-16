#include "dao/rsync.h"

bool
rsync_cleanup(struct rsync_ctx *ctx)
{
	return false;
}

struct rsync_dao *
rsyncdao_create(struct rsync_ctx *ctx)
{
	return NULL;
}

bool
rsyncdao_downgrade(struct rsync_dao *dao)
{
	return false;
}

struct cache_file *
rsyncdao_map(struct rsync_dao *dao, struct uri const *url)
{
	return NULL;
}

struct mft_meta const *
rsyncdao_fallback_mftnum(struct rsync_dao const *dao)
{
	return NULL;
}

void
rsyncdao_commit(struct rsync_dao *dao, struct rpp *rpp)
{
}

void
rsyncdao_free(struct rsync_dao *dao)
{
}
