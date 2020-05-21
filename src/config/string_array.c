#include "config/string_array.h"

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "config/str.h"

int
string_array_init(struct string_array *array, char const *const *values,
    size_t len)
{
	size_t i;

	array->length = len;

	if (len == 0) {
		array->array = NULL;
		return 0;
	}

	array->array = calloc(len, sizeof(char *));
	if (array->array == NULL)
		return -ENOMEM;

	for (i = 0; i < len; i++) {
		array->array[i] = strdup(values[i]);
		if (array->array[i] == NULL) {
			string_array_cleanup(array);
			return -ENOMEM;
		}
	}

	return 0;
}

void
string_array_cleanup(struct string_array *array)
{
	size_t i;
	for (i = 0; i < array->length; i++)
		free(array->array[i]);
	free(array->array);
}

static void
__string_array_free(struct string_array *array)
{
	string_array_cleanup(array);
	array->array = NULL;
	array->length = 0;
}

static void
string_array_print(struct option_field const *field, void *_value)
{
	struct string_array *value = _value;
	size_t i;

	pr_op_info("%s:", field->name);

	if (value->length == 0)
		pr_op_info("  <Nothing>");
	else for (i = 0; i < value->length; i++)
		pr_op_info("  %s", value->array[i]);
}

static int
string_array_parse_json(struct option_field const *opt, json_t *json,
    void *_result)
{
	struct string_array *result;
	json_t *child;
	size_t i, len;
	char const *tmp;
	int error;

	if (!json_is_array(json)) {
		return pr_op_err("The '%s' element is not a JSON array.",
		    opt->name);
	}

	len = json_array_size(json);
	if (len == 0) {
		__string_array_free(_result);
		return 0;
	}

	for (i = 0; i < len; i++) {
		child = json_array_get(json, i);
		if (!json_is_string(child)) {
			return pr_op_err("'%s' array element #%zu is not a string.",
			    opt->name, i);
		}
	}

	result = _result;

	/* Remove the previous value (usually the default). */
	__string_array_free(result);

	result->array = calloc(len, sizeof(char *));
	if (result->array == NULL)
		return pr_enomem();
	result->length = len;

	for (i = 0; i < len; i++) {
		error = parse_json_string(json_array_get(json, i),
		    "array element", &tmp);
		if (error)
			goto fail;

		result->array[i] = strdup(tmp);
		if (result->array[i] == NULL) {
			error = pr_enomem();
			goto fail;
		}
	}

	return 0;

fail:
	__string_array_free(result);
	return error;
}

static void
string_array_free(void *array)
{
	__string_array_free(array);
}

const struct global_type gt_string_array = {
	.has_arg = required_argument,
	.size = sizeof(char *const *),
	.print = string_array_print,
	.parse.json = string_array_parse_json,
	.free = string_array_free,
	.arg_doc = "<sequence of strings>",
};
