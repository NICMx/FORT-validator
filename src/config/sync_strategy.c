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

static void
print_sync_strategy(struct group_fields const *group,
    struct option_field const *field, void *value)
{
	enum sync_strategy *strategy = value;
	char const *str = "<unknown>";

	switch (*strategy) {
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

	pr_info("%s.%s: %s", group->name, field->name, str);
}

static int
parse_argv_sync_strategy(struct option_field const *field, char const *str,
    void *_result)
{
	enum sync_strategy *result = _result;

	if (strcmp(str, SYNC_VALUE_OFF) == 0)
		*result = SYNC_OFF;
	else if (strcmp(str, SYNC_VALUE_STRICT) == 0)
		*result = SYNC_STRICT;
	else if (strcmp(str, SYNC_VALUE_ROOT) == 0)
		*result = SYNC_ROOT;
	else if (strcmp(str, SYNC_VALUE_ROOT_EXCEPT_TA) == 0)
		*result = SYNC_ROOT_EXCEPT_TA;
	else
		return pr_err("Unknown synchronization strategy: '%s'", str);

	return 0;
}

static int
parse_toml_sync_strategy(struct option_field const *opt,
    struct toml_table_t *toml, void *_result)
{
	int error;
	char *string;

	error = parse_toml_string(toml, opt->name, &string);
	if (error)
		return error;
	if (string == NULL)
		return 0;

	error = parse_argv_sync_strategy(opt, string, _result);

	free(string);
	return error;
}

const struct global_type gt_sync_strategy = {
	.has_arg = required_argument,
	.size = sizeof(enum sync_strategy),
	.print = print_sync_strategy,
	.parse.argv = parse_argv_sync_strategy,
	.parse.toml = parse_toml_sync_strategy,
	.arg_doc = SYNC_VALUE_OFF
	    "|" SYNC_VALUE_STRICT
	    "|" SYNC_VALUE_ROOT
	    "|" SYNC_VALUE_ROOT_EXCEPT_TA,
};
