#include "config/rsync_strategy.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "config/str.h"

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
	return pr_op_err("Unknown rsync synchronization strategy: '%s'. In order to use it, recompile using flag ENABLE_STRICT_STRATEGY.",\
	    str);
#endif

void
print_rsync_strategy(struct option_field const *field, void *value)
{
	char const *str = "<unknown>";

	switch (DEREFERENCE(value)) {
	case RSYNC_STRICT:
		str = RSYNC_VALUE_STRICT;
		break;
	case RSYNC_ROOT:
		str = RSYNC_VALUE_ROOT;
		break;
	case RSYNC_ROOT_EXCEPT_TA:
		str = RSYNC_VALUE_ROOT_EXCEPT_TA;
		break;
	default:
		break;
	}

	pr_op_info("%s: %s", field->name, str);
}

int
parse_argv_rsync_strategy(struct option_field const *field, char const *str,
    void *result)
{
	if (strcmp(str, RSYNC_VALUE_STRICT) == 0)
		HANDLE_RSYNC_STRICT
	else if (strcmp(str, RSYNC_VALUE_ROOT) == 0)
		DEREFERENCE(result) = RSYNC_ROOT;
	else if (strcmp(str, RSYNC_VALUE_ROOT_EXCEPT_TA) == 0)
		DEREFERENCE(result) = RSYNC_ROOT_EXCEPT_TA;
	else
		return pr_op_err("Unknown rsync synchronization strategy: '%s'",
		    str);

	/* FIXME (later) Remove when sync-strategy is fully deprecated */
	config_set_sync_strategy(DEREFERENCE(result));

	return 0;
}

int
parse_json_rsync_strategy(struct option_field const *opt, struct json_t *json,
    void *result)
{
	char const *string;
	int error;

	error = parse_json_string(json, opt->name, &string);
	return error ? error : parse_argv_rsync_strategy(opt, string, result);
}

const struct global_type gt_rsync_strategy = {
	.has_arg = required_argument,
	.size = sizeof(enum rsync_strategy),
	.print = print_rsync_strategy,
	.parse.argv = parse_argv_rsync_strategy,
	.parse.json = parse_json_rsync_strategy,
	.arg_doc = RSYNC_VALUE_ROOT
	    "|" RSYNC_VALUE_ROOT_EXCEPT_TA
	    PRINT_STRICT_ARG_DOC,
};
