#include "config/str.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

#define DEREFERENCE(void_value) (*((char **) void_value))

static void
__string_free(char **string)
{
	free(*string);
	*string = NULL;
}

static void
string_print(struct option_field const *field, void *value)
{
	pr_info("%s: %s", field->name, DEREFERENCE(value));
}

static int
string_parse_argv(struct option_field const *field, char const *str,
    void *result)
{
	if (field->type->has_arg != required_argument || str == NULL) {
		return pr_err("String options ('%s' in this case) require an argument.",
		    field->name);
	}

	/* Remove the previous value (usually the default). */
	__string_free(result);

	DEREFERENCE(result) = strdup(str);
	return (DEREFERENCE(result) != NULL) ? 0 : pr_enomem();
}

static int
string_parse_json(struct option_field const *opt, json_t *json, void *result)
{
	char const *string;
	int error;

	error = parse_json_string(json, opt->name, &string);
	return error ? error : string_parse_argv(opt, string, result);
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
	.parse.json = string_parse_json,
	.free = string_free,
	.arg_doc = "<string>",
};

/**
 * *result must not be freed nor long-term stored.
 */
int
parse_json_string(json_t *json, char const *name, char const **result)
{
	if (!json_is_string(json))
		return pr_err("The '%s' element is not a JSON string.", name);

	*result = json_string_value(json);
	return 0;
}
