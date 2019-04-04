#include "config/uint.h"

#include <getopt.h>
#include <errno.h>
#include <stdlib.h>

#include "log.h"
#include "config/uint.h"

static void
print_u_int32(struct option_field const *field, void *value)
{
	pr_info("%s: %u", field->name, *((u_int32_t *) value));
}

static int
parse_argv_u_int32(struct option_field const *field, char const *str,
    void *result)
{
	unsigned int tmp;
	int error;

	error = parse_argv_u_int(field, str, &tmp);
	if (error)
		return error;

	/* Range already validated (from field->min and field->max). */
	*((u_int32_t *) result) = tmp;
	return 0;
}

static int
parse_json_u_int32(struct option_field const *opt, json_t *json, void *result)
{
	unsigned int tmp;
	int error;

	error = parse_json_u_int(opt, json, &tmp);
	if (error)
		return error;

	/* Range already validated (from opt->min and opt->max). */
	*((u_int32_t *) result) = tmp;
	return 0;
}

const struct global_type gt_u_int32 = {
	.has_arg = required_argument,
	.size = sizeof(u_int32_t),
	.print = print_u_int32,
	.parse.argv = parse_argv_u_int32,
	.parse.json = parse_json_u_int32,
	.arg_doc = "<32-bit unsigned integer>",
};
