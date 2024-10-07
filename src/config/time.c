#include "config/time.h"

#include <errno.h>
#include <getopt.h>
#include <time.h>

#include "common.h"
#include "log.h"

static void
print_time(struct option_field const *field, void *value)
{
	time_t tt;
	char str[FORT_TS_LEN];
	int error;

	tt = *((time_t *)value);
	if (tt == 0)
		return;

	error = time2str(tt, str);
	if (error)
		pr_crit("time2str: %d", error);

	pr_op_info("%s: %s", field->name, str);
}

static int
parse_argv_time(struct option_field const *field, char const *str,
    void *result)
{
	if (str == NULL || strlen(str) == 0)
		return pr_op_err("--%s needs an argument.", field->name);

	return str2time(str, result);
}

static int
parse_json_time(struct option_field const *opt, json_t *json, void *result)
{
	if (!json_is_string(json))
		return pr_op_err("The '%s' element is not a JSON string.",
		    opt->name);

	return str2time(json_string_value(json), result);
}

const struct global_type gt_time = {
	.has_arg = required_argument,
	.size = sizeof(time_t),
	.print = print_time,
	.parse.argv = parse_argv_time,
	.parse.json = parse_json_time,
	.arg_doc = FORT_TS_FORMAT,
};
