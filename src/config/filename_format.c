#include "config/filename_format.h"

#include <getopt.h>

#include "config/str.h"
#include "log.h"

#define FNF_VALUE_GLOBAL "global-url"
#define FNF_VALUE_LOCAL "local-path"
#define FNF_VALUE_NAME "file-name"

#define DEREFERENCE(void_value) (*((enum filename_format *) void_value))

static void
print_filename_format(struct option_field const *field, void *value)
{
	char const *str = "<unknown>";

	switch (DEREFERENCE(value)) {
	case FNF_GLOBAL:
		str = FNF_VALUE_GLOBAL;
		break;
	case FNF_LOCAL:
		str = FNF_VALUE_LOCAL;
		break;
	case FNF_NAME:
		str = FNF_VALUE_NAME;
		break;
	}

	pr_op_info("%s: %s", field->name, str);
}

static int
parse_argv_filename_format(struct option_field const *field, char const *str,
    void *result)
{
	if (strcmp(str, FNF_VALUE_GLOBAL) == 0)
		DEREFERENCE(result) = FNF_GLOBAL;
	else if (strcmp(str, FNF_VALUE_LOCAL) == 0)
		DEREFERENCE(result) = FNF_LOCAL;
	else if (strcmp(str, FNF_VALUE_NAME) == 0)
		DEREFERENCE(result) = FNF_NAME;
	else
		return pr_op_err("Unknown file name format %s: '%s'",
		    field->name, str);

	return 0;
}

static int
parse_json_filename_format(struct option_field const *opt, json_t *json,
    void *result)
{
	char const *string;
	int error;

	error = parse_json_string(json, opt->name, &string);
	return error ? error : parse_argv_filename_format(opt, string, result);
}

const struct global_type gt_filename_format = {
	.has_arg = required_argument,
	.size = sizeof(enum filename_format),
	.print = print_filename_format,
	.parse.argv = parse_argv_filename_format,
	.parse.json = parse_json_filename_format,
	.arg_doc = FNF_VALUE_GLOBAL "|" FNF_VALUE_LOCAL "|" FNF_VALUE_NAME,
};
