#include "config/ts.h"

#include <getopt.h>
#include <string.h>

#include "common.h"
#include "log.h"

#define TST_STR_OFF "off"
#define TST_STR_UTC "utc"
#define TST_STR_LOCAL "local"

#define DEREFERENCE_UINT(void_value) (*((enum ts_type *) void_value))

static void
print_ts(struct option_field const *field, void *value)
{
	char const *str = "<unknown>";

	switch (DEREFERENCE_UINT(value)) {
	case TST_OFF:
		str = TST_STR_OFF;
		break;
	case TST_UTC:
		str = TST_STR_UTC;
		break;
	case TST_LOCAL:
		str = TST_STR_LOCAL;
		break;
	}

	pr_inf("%s: %s", field->name, str);
}

static enum ts_type
str2tst(struct option_field const *field, char const *str)
{
	if (strcmp(str, TST_STR_OFF) == 0)
		return TST_OFF;
	if (strcmp(str, TST_STR_UTC) == 0)
		return TST_UTC;
	if (strcmp(str, TST_STR_LOCAL) == 0)
		return TST_LOCAL;
	return pr_err("Unknown %s: '%s'", field->name, str);
}

static int
parse_argv_ts(struct option_field const *field, char const *str,
    void *result)
{
	DEREFERENCE_UINT(result) = str2tst(field, str);
	return 0;
}

static int
parse_json_ts(struct option_field const *opt, json_t *json, void *result)
{
	if (!json_is_string(json))
		return pr_err("The '%s' element is not a JSON string.",
		    opt->name);

	DEREFERENCE_UINT(result) = str2tst(opt, json_string_value(json));
	return 0;
}

const struct global_type gt_timestamp_type = {
	.has_arg = required_argument,
	.size = sizeof(enum ts_type),
	.print = print_ts,
	.parse.argv = parse_argv_ts,
	.parse.json = parse_json_ts,
	.arg_doc = TST_STR_OFF "|" TST_STR_UTC "|" TST_STR_LOCAL,
};
