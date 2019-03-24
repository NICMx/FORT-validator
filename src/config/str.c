#include "config/str.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

static void
__string_free(char **string)
{
	free(*string);
	*string = NULL;
}

static void
string_print(struct group_fields const *group, struct option_field const *field,
    void *value)
{
	pr_info("%s.%s: %s", group->name, field->name, *((char **) value));
}

static int
string_parse_argv(struct option_field const *field, char const *str,
    void *_result)
{
	char **result = _result;

	if (field->type->has_arg != required_argument || str == NULL) {
		return pr_err("String options ('%s' in this case) require an argument.",
		    field->name);
	}

	/* Remove the previous value (usually the default). */
	__string_free(result);

	/* tomlc99 frees @str early, so work with a copy. */
	*result = strdup(str);
	return ((*result) != NULL) ? 0 : pr_enomem();
}

static int
string_parse_toml(struct option_field const *opt, struct toml_table_t *toml,
    void *_result)
{
	char *tmp;
	char **result;
	int error;

	error = parse_toml_string(toml, opt->name, &tmp);
	if (error)
		return error;
	if (tmp == NULL)
		return 0;

	result = _result;
	__string_free(result);
	*result = tmp;
	return 0;
}

static void
string_free(void *string)
{
	__string_free(string);
}

const struct global_type gt_string = {
	.has_arg = required_argument,
	.size = sizeof(char *),
	.print = string_print,
	.parse.argv = string_parse_argv,
	.parse.toml = string_parse_toml,
	.free = string_free,
	.arg_doc = "<string>",
};

int
parse_toml_string(struct toml_table_t *toml, char const *name, char **result)
{
	const char *raw;
	char *value;

	raw = toml_raw_in(toml, name);
	if (raw == NULL) {
		*result = NULL;
		return 0;
	}
	if (toml_rtos(raw, &value) == -1)
		return pr_err("Cannot parse '%s' as a string.", raw);

	*result = value;
	return 0;
}
