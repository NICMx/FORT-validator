#include "config/filename_format.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "config/str.h"

#define FNF_VALUE_GLOBAL "global-url"
#define FNF_VALUE_LOCAL "local-path"
#define FNF_VALUE_NAME "file-name"

static void
print_filename_format(struct group_fields const *group,
    struct option_field const *field, void *value)
{
	enum filename_format *format = value;
	char const *str = "<unknown>";

	switch (*format) {
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

	pr_info("%s.%s: %s", group->name, field->name, str);
}

static int
parse_argv_filename_format(struct option_field const *field, char const *str,
    void *_result)
{
	enum filename_format *result = _result;

	if (strcmp(str, FNF_VALUE_GLOBAL) == 0)
		*result = FNF_GLOBAL;
	else if (strcmp(str, FNF_VALUE_LOCAL) == 0)
		*result = FNF_LOCAL;
	else if (strcmp(str, FNF_VALUE_NAME) == 0)
		*result = FNF_NAME;
	else
		return pr_err("Unknown file name format: '%s'", str);

	return 0;
}

static int
parse_toml_filename_format(struct option_field const *opt,
    struct toml_table_t *toml, void *_result)
{
	char *string;
	int error;

	error = parse_toml_string(toml, opt->name, &string);
	if (error)
		return error;
	if (string == NULL)
		return 0;

	error = parse_argv_filename_format(opt, string, _result);

	free(string);
	return error;
}

const struct global_type gt_filename_format = {
	.has_arg = required_argument,
	.size = sizeof(enum filename_format),
	.print = print_filename_format,
	.parse.argv = parse_argv_filename_format,
	.parse.toml = parse_toml_filename_format,
	.arg_doc = FNF_VALUE_GLOBAL "|" FNF_VALUE_LOCAL "|" FNF_VALUE_NAME,
};
