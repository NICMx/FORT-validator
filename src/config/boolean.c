#include "config/boolean.h"

#include <getopt.h>
#include <string.h>

#include "log.h"

#define DEREFERENCE(void_value) (*((bool *) void_value))

void
print_bool(struct option_field const *field, void *value)
{
	pr_op_info("%s: %s", field->name, DEREFERENCE(value) ? "true" : "false");
}

int
parse_argv_bool(struct option_field const *field, char const *str, void *result)
{
	if (str == NULL || strlen(str) == 0) {
		DEREFERENCE(result) = true;
		return 0;
	}

	if (strcmp(str, "true") == 0) {
		DEREFERENCE(result) = true;
		return 0;
	}

	if (strcmp(str, "false") == 0) {
		DEREFERENCE(result) = false;
		return 0;
	}

	return pr_op_err("Invalid %s: '%s', must be boolean (true|false)",
	    field->name, str);
}

int
parse_json_bool(struct option_field const *opt, struct json_t *json,
    void *result)
{
	if (!json_is_boolean(json)) {
		return pr_op_err("The '%s' element is not a JSON boolean.",
		    opt->name);
	}

	DEREFERENCE(result) = json_boolean_value(json);
	return 0;
}

const struct global_type gt_bool = {
	.has_arg = optional_argument,
	.size = sizeof(bool),
	.print = print_bool,
	.parse.argv = parse_argv_bool,
	.parse.json = parse_json_bool,
	.arg_doc = "true|false",
};
