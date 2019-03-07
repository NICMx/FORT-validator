#include "config/uint.h"

#include <getopt.h>
#include <errno.h>
#include <stdlib.h>
#include "log.h"

static void
print_u_int(struct group_fields const *group, struct option_field const *field,
    void *value)
{
	pr_info("%s.%s: %u", group->name, field->name,
	    *((unsigned int *) value));
}

static int
parse_argv_u_int(struct option_field const *field, char const *str,
    void *_result)
{
	unsigned long parsed;
	int *result;

	if (field->type->has_arg != required_argument || str == NULL) {
		return pr_err("Integer options ('%s' in this case) require an argument.",
		    field->name);
	}

	errno = 0;
	parsed = strtoul(str, NULL, 10);
	if (errno)
		return pr_errno(errno, "'%s' is not an unsigned integer", str);

	if (parsed < field->min || field->max < parsed) {
		return pr_err("'%lu' is out of bounds (%u-%u).", parsed,
		    field->min, field->max);
	}

	result = _result;
	*result = parsed;
	return 0;
}

static int
parse_toml_u_int(struct option_field const *opt, struct toml_table_t *toml,
    void *_result)
{
	const char *raw;
	int64_t value;
	unsigned int *result;

	raw = toml_raw_in(toml, opt->name);
	if (raw == NULL)
		return pr_err("TOML integer '%s' was not found.", opt->name);
	if (toml_rtoi(raw, &value) == -1)
		return pr_err("Cannot parse '%s' as an integer.", raw);

	if (value < opt->min || opt->max < value) {
		return pr_err("Integer '%s' is out of range (%u-%u).",
		    opt->name, opt->min, opt->max);
	}

	result = _result;
	*result = value;
	return 0;
}

const struct global_type gt_u_int = {
	.has_arg = required_argument,
	.size = sizeof(unsigned int),
	.print = print_u_int,
	.parse.argv = parse_argv_u_int,
	.parse.toml = parse_toml_u_int,
	.arg_doc = "<unsigned integer>",
};
