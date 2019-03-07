#include "config/str.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

static void
print_string(struct group_fields const *group, struct option_field const *field,
    void *value)
{
	pr_info("%s.%s: %s", group->name, field->name, *((char **) value));
}

static int
parse_argv_string(struct option_field const *field, char const *str,
    void *_result)
{
	char **result = _result;

	/* Remove the previous value (usually the default). */
	field->type->free(result);

	if (field->type->has_arg != required_argument || str == NULL) {
		return pr_err("String options ('%s' in this case) require an argument.",
		    field->name);
	}

	/* tomlc99 frees @str early, so work with a copy. */
	*result = strdup(str);
	return ((*result) != NULL) ? 0 : pr_enomem();
}

int
parse_toml_string(struct option_field const *opt, struct toml_table_t *toml,
    void *_result)
{
	const char *raw;
	char *value;
	char **result;

	/* Remove the previous value (usually the default). */
	opt->type->free(_result);

	raw = toml_raw_in(toml, opt->name);
	if (raw == NULL)
		return pr_err("TOML string '%s' was not found.", opt->name);
	if (toml_rtos(raw, &value) == -1)
		return pr_err("Cannot parse '%s' as a string.", raw);

	result = _result;
	*result = value;
	return 0;
}

static void
free_string(void *_string)
{
	char **string = _string;
	free(*string);
	*string = NULL;
}

const struct global_type gt_string = {
	.has_arg = required_argument,
	.size = sizeof(char *),
	.print = print_string,
	.parse.argv = parse_argv_string,
	.parse.toml = parse_toml_string,
	.free = free_string,
	.arg_doc = "<string>",
};
