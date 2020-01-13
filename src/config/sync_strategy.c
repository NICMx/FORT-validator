#include "config/sync_strategy.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "config/str.h"
#include "config/rsync_strategy.h"

/*
 * Yeap, all of this is duplicated, better remove it with the whole source file
 * whenever sync-strategy isn't supported anymore.
 */

#define RSYNC_VALUE_OFF			"off"
#define RSYNC_VALUE_STRICT		"strict"
#define RSYNC_VALUE_ROOT		"root"
#define RSYNC_VALUE_ROOT_EXCEPT_TA	"root-except-ta"

#define DEREFERENCE(void_value) (*((enum rsync_strategy *) void_value))

#ifdef ENABLE_STRICT_STRATEGY
#define PRINT_STRICT_ARG_DOC "|" RSYNC_VALUE_STRICT
#define HANDLE_RSYNC_STRICT DEREFERENCE(result) = RSYNC_STRICT;
#else
#define PRINT_STRICT_ARG_DOC
#define HANDLE_RSYNC_STRICT						\
	return pr_err("Unknown synchronization strategy: '%s'. In order to use it, recompile using flag ENABLE_STRICT_STRATEGY.",\
	    str);
#endif

static void
print_sync_strategy(struct option_field const *field, void *value)
{
	if (DEREFERENCE(value) == RSYNC_OFF) {
		pr_info("%s: %s", field->name, RSYNC_VALUE_OFF);
		return;
	}

	print_rsync_strategy(field, value);
}

static int
parse_argv_sync_strategy(struct option_field const *field, char const *str,
    void *result)
{
	pr_warn("'sync-strategy' will be deprecated.");
	pr_warn("Use 'rsync.strategy' instead; or 'rsync.enabled=false' if you wish to use 'off' strategy.");

	if (strcmp(str, RSYNC_VALUE_OFF) == 0) {
		DEREFERENCE(result) = RSYNC_OFF;
		config_set_rsync_enabled(false);
		return 0;
	}

	return parse_argv_rsync_strategy(field, str, result);
}

static int
parse_json_sync_strategy(struct option_field const *opt, struct json_t *json,
    void *result)
{
	char const *string;
	int error;

	error = parse_json_string(json, opt->name, &string);
	return error ? error : parse_argv_sync_strategy(opt, string, result);
}

const struct global_type gt_sync_strategy = {
	.has_arg = required_argument,
	.size = sizeof(enum rsync_strategy),
	.print = print_sync_strategy,
	.parse.argv = parse_argv_sync_strategy,
	.parse.json = parse_json_sync_strategy,
	.arg_doc = RSYNC_VALUE_OFF
	    "|" RSYNC_VALUE_ROOT
	    "|" RSYNC_VALUE_ROOT_EXCEPT_TA
	    PRINT_STRICT_ARG_DOC,
};
