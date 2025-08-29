#include "config/str.h"

#include <getopt.h>

#include "alloc.h"
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
	pr_op_info("%s: %s", field->name, DEREFERENCE(value));
}

static int
string_parse_argv(struct option_field const *field, char const *str,
    void *result)
{
	if (field->type->has_arg != required_argument || str == NULL ||
	    strlen(str) == 0) {
		return pr_op_err("String options ('%s' in this case) require an argument.",
		    field->name);
	}

	/* Remove the previous value (usually the default). */
	__string_free(result);

	DEREFERENCE(result) = pstrdup(str);
	return 0;
}

static int
string_parse_json(struct option_field const *opt, json_t *json, void *result)
{
	char const *string;
	int error;

	string = NULL;
	error = parse_json_string(json, opt->name, &string);
	if (error)
		return error;

	if (string == NULL) {
		if (opt->json_null_allowed) {
			DEREFERENCE(result) = NULL;
			return 0;
		} else {
			if (string == NULL) {
				return pr_op_err(
				    "The '%s' field is not allowed to be null.",
				    opt->name);
			}
		}
	}

	return string_parse_argv(opt, string, result);
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

static int
service_parse_json(struct option_field const *opt, json_t *json, void *result)
{
	json_int_t intval;
	char *strval;
	int written;

	if (json_is_integer(json)) {
		intval = json_integer_value(json);
		if (intval < 1 || 65535 < intval) {
			return pr_op_err("'%s' is out of range (1-65535).",
			    opt->name);
		}

		strval = pmalloc(6);
		written = snprintf(strval, 6, JSON_INTEGER_FORMAT, intval);
		if (written < 0 || 6 <= written)
			return pr_op_err("Cannot convert '%s' to string: snprintf returned %d",
			    opt->name, written);

		DEREFERENCE(result) = strval;
		return 0;
	}

	return string_parse_json(opt, json, result);
}

const struct global_type gt_service = {
	.has_arg = required_argument,
	.size = sizeof(char *),
	.print = string_print,
	.parse.argv = string_parse_argv,
	.parse.json = service_parse_json,
	.free = string_free,
	.arg_doc = "<port>",
};

/**
 * *result must not be freed nor long-term stored.
 */
int
parse_json_string(json_t *json, char const *name, char const **result)
{
	if (json_is_null(json)) {
		*result = NULL;
		return 0;
	}

	if (!json_is_string(json))
		return pr_op_err("The '%s' element is not a JSON string.", name);

	*result = json_string_value(json);
	return 0;
}
