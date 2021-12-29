#include "config/rsync_strategy.h"

#include <getopt.h>
#include "log.h"

static void
print_rsync_strategy(struct option_field const *field, void *value)
{
	/* Deprecated. */
}

static int
parse_argv_rsync_strategy(struct option_field const *field, char const *str,
    void *result)
{
	return pr_op_warn("--rsync.strategy is deprecated; please remove it.");
}

static int
parse_json_rsync_strategy(struct option_field const *opt, struct json_t *json,
    void *result)
{
	return pr_op_warn("rsync.strategy is deprecated; please remove it.");
}

const struct global_type gt_rsync_strategy = {
	.has_arg = required_argument,
	.size = sizeof(enum rsync_strategy),
	.print = print_rsync_strategy,
	.parse.argv = parse_argv_rsync_strategy,
	.parse.json = parse_json_rsync_strategy,
	.arg_doc = "strict|root|root-except-ta",
};
