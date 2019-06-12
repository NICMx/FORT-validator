#include "config/sync_strategy.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "config/str.h"

#define SYNC_VALUE_OFF			"off"
#define SYNC_VALUE_STRICT		"strict"
#define SYNC_VALUE_ROOT			"root"
#define SYNC_VALUE_ROOT_EXCEPT_TA	"root-except-ta"

#define DEREFERENCE(void_value) (*((enum sync_strategy *) void_value))

#ifdef ENABLE_STRICT_STRATEGY
#define PRINT_STRICT_ARG_DOC "|" SYNC_VALUE_STRICT
#define HANDLE_SYNC_STRICT DEREFERENCE(result) = SYNC_STRICT;
#else
#define PRINT_STRICT_ARG_DOC
#define HANDLE_SYNC_STRICT						\
	return pr_err("Unknown synchronization strategy: '%s'. In order to use it, recompile using flag ENABLE_STRICT_STRATEGY.",\
	    str);
#endif

static void
print_sync_strategy(struct option_field const *field, void *value)
{
	char const *str = "<unknown>";

	switch (DEREFERENCE(value)) {
	case SYNC_OFF:
		str = SYNC_VALUE_OFF;
		break;
	case SYNC_STRICT:
		str = SYNC_VALUE_STRICT;
		break;
	case SYNC_ROOT:
		str = SYNC_VALUE_ROOT;
		break;
	case SYNC_ROOT_EXCEPT_TA:
		str = SYNC_VALUE_ROOT_EXCEPT_TA;
		break;
	}

	pr_info("%s: %s", field->name, str);
}

static int
parse_argv_sync_strategy(struct option_field const *field, char const *str,
    void *result)
{
	if (strcmp(str, SYNC_VALUE_OFF) == 0)
		DEREFERENCE(result) = SYNC_OFF;
	else if (strcmp(str, SYNC_VALUE_STRICT) == 0)
		HANDLE_SYNC_STRICT
	else if (strcmp(str, SYNC_VALUE_ROOT) == 0)
		DEREFERENCE(result) = SYNC_ROOT;
	else if (strcmp(str, SYNC_VALUE_ROOT_EXCEPT_TA) == 0)
		DEREFERENCE(result) = SYNC_ROOT_EXCEPT_TA;
	else
		return pr_err("Unknown synchronization strategy: '%s'", str);

	return 0;
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
	.size = sizeof(enum sync_strategy),
	.print = print_sync_strategy,
	.parse.argv = parse_argv_sync_strategy,
	.parse.json = parse_json_sync_strategy,
	.arg_doc = SYNC_VALUE_OFF
	    PRINT_STRICT_ARG_DOC
	    "|" SYNC_VALUE_ROOT
	    "|" SYNC_VALUE_ROOT_EXCEPT_TA,
};
