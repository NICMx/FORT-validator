#include "config/work_offline.h"

#include <getopt.h>
#include <stdbool.h>

#include "config.h"
#include "config/boolean.h"

#define DEREFERENCE(void_value) (*((bool *) void_value))

static int
parse_argv_offline(struct option_field const *field, char const *str, void *result)
{
	int error;

	error = parse_argv_bool(field, str, result);
	if (error)
		return error;

	config_set_rsync_enabled(!DEREFERENCE(result));
	config_set_rrdp_enabled(!DEREFERENCE(result));
	config_set_http_enabled(!DEREFERENCE(result));

	return 0;
}

static int
parse_json_offline(struct option_field const *opt, struct json_t *json,
    void *result)
{
	int error;

	error = parse_json_bool(opt, json, result);
	if (error)
		return error;

	config_set_rsync_enabled(!DEREFERENCE(result));
	config_set_rrdp_enabled(!DEREFERENCE(result));
	config_set_http_enabled(!DEREFERENCE(result));

	return 0;
}

const struct global_type gt_work_offline = {
	.has_arg = optional_argument,
	.size = sizeof(bool),
	.print = print_bool,
	.parse.argv = parse_argv_offline,
	.parse.json = parse_json_offline,
	.arg_doc = "true|false",
};
