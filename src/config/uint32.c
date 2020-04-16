#include "config/uint32.h"

#include <getopt.h>
#include <errno.h>
#include <stdlib.h>

#include "log.h"
#include "config/uint.h"

static void
print_uint32(struct option_field const *field, void *value)
{
	pr_info("%s: %u", field->name, *((uint32_t *) value));
}

static int
parse_argv_uint32(struct option_field const *field, char const *str,
    void *result)
{
	unsigned int tmp;
	int error;

	error = parse_argv_uint(field, str, &tmp);
	if (error)
		return error;

	/* Range already validated (from field->min and field->max). */
	*((uint32_t *) result) = tmp;
	return 0;
}

static int
parse_json_uint32(struct option_field const *opt, json_t *json, void *result)
{
	unsigned int tmp;
	int error;

	error = parse_json_uint(opt, json, &tmp);
	if (error)
		return error;

	/* Range already validated (from opt->min and opt->max). */
	*((uint32_t *) result) = tmp;
	return 0;
}

const struct global_type gt_uint32 = {
	.has_arg = required_argument,
	.size = sizeof(uint32_t),
	.print = print_uint32,
	.parse.argv = parse_argv_uint32,
	.parse.json = parse_json_uint32,
	.arg_doc = "<32-bit unsigned integer>",
};
