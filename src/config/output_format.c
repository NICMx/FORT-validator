#include "config/output_format.h"

#include <getopt.h>
#include <string.h>

#include "config/str.h"
#include "log.h"

#define OFM_VALUE_CSV  "csv"
#define OFM_VALUE_JSON "json"

#define DEREFERENCE(void_value) (*((enum output_format *) void_value))

static void
print_output_format(struct option_field const *field, void *value)
{
	char const *str = "<unknown>";

	switch (DEREFERENCE(value)) {
	case OFM_CSV:
		str = OFM_VALUE_CSV;
		break;
	case OFM_JSON:
		str = OFM_VALUE_JSON;
		break;
	}

	pr_op_info("%s: %s", field->name, str);
}

static int
parse_argv_output_format(struct option_field const *field, char const *str,
    void *result)
{
	if (strcmp(str, OFM_VALUE_CSV) == 0)
		DEREFERENCE(result) = OFM_CSV;
	else if (strcmp(str, OFM_VALUE_JSON) == 0)
		DEREFERENCE(result) = OFM_JSON;
	else
		return pr_op_err("Unknown output format %s: '%s'",
		    field->name, str);

	return 0;
}

static int
parse_json_output_format(struct option_field const *opt, json_t *json,
    void *result)
{
	char const *string;
	int error;

	error = parse_json_string(json, opt->name, &string);
	return error ? error : parse_argv_output_format(opt, string, result);
}

const struct global_type gt_output_format = {
	.has_arg = required_argument,
	.size = sizeof(enum output_format),
	.print = print_output_format,
	.parse.argv = parse_argv_output_format,
	.parse.json = parse_json_output_format,
	.arg_doc = OFM_VALUE_CSV "|" OFM_VALUE_JSON,
};
