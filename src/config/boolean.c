#include "config/boolean.h"

#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include "log.h"

static void
print_bool(struct group_fields const *group, struct option_field const *field,
    void *_value)
{
	bool *value = _value;
	pr_info("%s.%s: %s", group->name, field->name,
	    (*value) ? "true" : "false");
}

static int
parse_argv_bool(struct option_field const *field, char const *str, void *result)
{
	bool *value = result;

	if (str == NULL) {
		*value = true;
		return 0;
	}

	if (strcmp(str, "true") == 0) {
		*value = true;
		return 0;
	}

	if (strcmp(str, "false") == 0) {
		*value = false;
		return 0;
	}

	return pr_err("Cannot parse '%s' as a bool (true|false).", str);
}

static int
parse_toml_bool(struct option_field const *opt, struct toml_table_t *toml,
    void *_result)
{
	const char *raw;
	int value;
	bool *result;

	raw = toml_raw_in(toml, opt->name);
	if (raw == NULL)
		return pr_err("TOML boolean '%s' was not found.", opt->name);
	if (toml_rtob(raw, &value) == -1)
		return pr_err("Cannot parse '%s' as a boolean.", raw);

	result = _result;
	*result = value;
	return 0;
}

const struct global_type gt_bool = {
	.has_arg = no_argument,
	.size = sizeof(bool),
	.print = print_bool,
	.parse.argv = parse_argv_bool,
	.parse.toml = parse_toml_bool,
	.arg_doc = "true|false",
};
