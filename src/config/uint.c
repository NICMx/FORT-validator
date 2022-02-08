#include "config/uint.h"

#include <getopt.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

void
print_uint(struct option_field const *field, void *value)
{
	pr_op_info("%s: %u", field->name, *((unsigned int *) value));
}

int
parse_argv_uint(struct option_field const *field, char const *str,
    void *result)
{
	char *tmp;
	unsigned long parsed;

	if (field->type->has_arg != required_argument || str == NULL ||
		    strlen(str) == 0) {
		return pr_op_err("Integer options ('%s' in this case) require an argument.",
		    field->name);
	}

	errno = 0;
	parsed = strtoul(str, &tmp, 10);
	if (errno || *tmp != '\0')
		return errno ? pr_op_errno(errno,
		    "Value '%s' at '%s' is not an unsigned integer", str,
		    field->name) :
		    pr_op_err("Value '%s' at '%s' is not an unsigned integer",
		    str, field->name);

	if (parsed < field->min || field->max < parsed) {
		return pr_op_err("Value of '%s' is out of range (%u-%u).",
		    field->name, field->min, field->max);
	}

	*((unsigned int *) result) = parsed;
	return 0;
}

int
parse_json_uint(struct option_field const *opt, json_t *json, void *result)
{
	json_int_t value;

	if (!json_is_integer(json)) {
		return pr_op_err("The '%s' element is not a JSON integer.",
		    opt->name);
	}

	value = json_integer_value(json);

	if (value < opt->min || opt->max < value) {
		return pr_op_err("Integer '%s' is out of range (%u-%u).",
		    opt->name, opt->min, opt->max);
	}

	*((unsigned int *) result) = value;
	return 0;
}

const struct global_type gt_uint = {
	.has_arg = required_argument,
	.size = sizeof(unsigned int),
	.print = print_uint,
	.parse.argv = parse_argv_uint,
	.parse.json = parse_json_uint,
	.arg_doc = "<unsigned integer>",
};

static int
parse_argv_uint_deprecated(struct option_field const *field, char const *str,
    void *result)
{
	pr_op_warn("Warning: Option '%s' is deprecated.", field->name);
	return parse_argv_uint(field, str, result);
}

static int
parse_json_uint_deprecated(struct option_field const *opt, json_t *json,
    void *result)
{
	pr_op_warn("Warning: Option '%s' is deprecated.", opt->name);
	return parse_json_uint(opt, json, result);
}

const struct global_type gt_uint_deprecated = {
	.has_arg = required_argument,
	.size = sizeof(unsigned int),
	.print = print_uint,
	.parse.argv = parse_argv_uint_deprecated,
	.parse.json = parse_json_uint_deprecated,
	.arg_doc = "<unsigned integer>",
};
