#include "ta.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>

#include "alloc.h"
#include "file.h"

struct ta_context {
	char *refresh_path;
	char *fallback_path;
	atomic_uint refresh_commits;
	atomic_uint fallback_commits;
};

struct ta_context *
tactx_create(char const *fallback)
{
	struct ta_context *ctx;

	ctx = pmalloc(sizeof(struct ta_context));
	ctx->refresh_path = NULL;
	ctx->fallback_path = fallback ? pstrdup(fallback) : NULL;
	atomic_init(&ctx->refresh_commits, 0);
	atomic_init(&ctx->fallback_commits, 0);

	return ctx;
}

void
tactx_free(struct ta_context *ctx)
{
	if (!ctx)
		return;

	if (ctx->refresh_path != ctx->fallback_path)
		free(ctx->refresh_path);
	free(ctx->fallback_path);
	free(ctx);
}

void
tactx_set_refresh(struct ta_context *ctx, char const *refresh)
{
	ctx->refresh_path = pstrdup(refresh);
}

void
tactx_set_unchanged(struct ta_context *ctx)
{
	ctx->refresh_path = ctx->fallback_path;
}

char const *
tactx_map(struct ta_context *ctx, bool refresh)
{
	return refresh ? ctx->refresh_path : ctx->fallback_path;
}

void
tactx_preserve(struct ta_context *ctx, bool refresh)
{
	atomic_fetch_add(
	    refresh ? &ctx->refresh_commits : &ctx->fallback_commits,
	    1
	);
}

void
tactx_print(char const *pfx, struct ta_context *ctx)
{
	printf("%s:\n", pfx);

	if (ctx == NULL) {
		printf("\tNULL\n");
		return;
	}

	printf("\tRefresh: %s (commits: %u)\n", ctx->refresh_path,
	    atomic_fetch_add(&ctx->refresh_commits, 0));
	printf("\tFallback: %s (commits: %u)\n", ctx->fallback_path,
	    atomic_fetch_add(&ctx->fallback_commits, 0));
}

bool
tactx_cleanup(struct ta_context *ctx, char const *node_path)
{
	if (!ctx)
		return false;

	if (atomic_load(&ctx->refresh_commits) > 0)
		return (ctx->refresh_path == ctx->fallback_path)
		    ? true
		    : !file_mv(ctx->refresh_path, node_path);

	if (atomic_load(&ctx->fallback_commits) > 0)
		return true;

	file_rm_f(ctx->refresh_path);
	file_rm_f(ctx->fallback_path);
	return false;
}
