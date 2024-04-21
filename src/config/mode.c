#include "config/mode.h"

#include <getopt.h>

#include "log.h"
#include "config/str.h"

#define VALUE_SERVER		"server"
#define VALUE_STANDALONE	"standalone"
#define VALUE_PRINT_FILE	"print"

#define DEREFERENCE(void_value) (*((enum mode *) void_value))

static void
print_mode(struct option_field const *field, void *value)
{
	char const *str = "<unknown>";

	switch (DEREFERENCE(value)) {
	case SERVER:
		str = VALUE_SERVER;
		break;
	case STANDALONE:
		str = VALUE_STANDALONE;
		break;
	case PRINT_FILE:
		str = VALUE_PRINT_FILE;
		break;
	}

	pr_op_info("%s: %s", field->name, str);
}

static int
parse_argv_mode(struct option_field const *field, char const *str,
    void *result)
{
	if (strcmp(str, VALUE_SERVER) == 0)
		DEREFERENCE(result) = SERVER;
	else if (strcmp(str, VALUE_STANDALONE) == 0)
		DEREFERENCE(result) = STANDALONE;
	else if (strcmp(str, VALUE_PRINT_FILE) == 0)
		DEREFERENCE(result) = PRINT_FILE;
	else
		return pr_op_err("Unknown mode: '%s'", str);

	return 0;
}

static int
parse_json_mode(struct option_field const *opt, struct json_t *json,
    void *result)
{
	char const *string;
	int error;

	error = parse_json_string(json, opt->name, &string);
	return error ? error : parse_argv_mode(opt, string, result);
}

const struct global_type gt_mode = {
	.has_arg = required_argument,
	.size = sizeof(enum mode),
	.print = print_mode,
	.parse.argv = parse_argv_mode,
	.parse.json = parse_json_mode,
	.arg_doc = VALUE_SERVER "|" VALUE_STANDALONE "|" VALUE_PRINT_FILE,
};
