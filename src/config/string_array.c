#include "config/string_array.h"

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

int
string_array_init(struct string_array *array, char const *const *values,
    size_t len)
{
	size_t i;

	array->length = len;

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
string_array_print(struct group_fields const *group,
    struct option_field const *field, void *_value)
{
	struct string_array *value = _value;
	size_t i;

	pr_info("%s.%s:", group->name, field->name);
	pr_indent_add();

	if (value->length == 0)
		pr_info("<Nothing>");
	else for (i = 0; i < value->length; i++)
		pr_info("%s", value->array[i]);

	pr_indent_rm();
}

static int
string_array_parse_toml(struct option_field const *opt,
    struct toml_table_t *toml, void *_result)
{
	toml_array_t *array;
	int array_len;
	int i;
	const char *raw;
	struct string_array *result = _result;
	int error;

	array = toml_array_in(toml, opt->name);
	if (array == NULL)
		return 0;
	array_len = toml_array_nelem(array);

	/* Remove the previous value (usually the default). */
	__string_array_free(result);

	result->array = malloc(array_len * sizeof(char *));
	if (result->array == NULL)
		return pr_enomem();
	result->length = array_len;

	for (i = 0; i < array_len; i++) {
		raw = toml_raw_at(array, i);
		if (raw == NULL) {
			error = pr_crit("Array index %d is NULL.", i);
			goto fail;
		}
		if (toml_rtos(raw, &result->array[i]) == -1) {
			error = pr_err("Cannot parse '%s' as a string.", raw);
			goto fail;
		}
	}

	return 0;

fail:
	free(result->array);
	result->length = 0;
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
	.parse.toml = string_array_parse_toml,
	.free = string_array_free,
	.arg_doc = "<sequence of strings>",
};
