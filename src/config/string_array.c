#include "config/string_array.h"

#include <getopt.h>
#include <stdlib.h>
#include "log.h"

static void
print_string_array(struct group_fields const *group,
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
parse_toml_string_array(struct option_field const *opt,
    struct toml_table_t *toml, void *_result)
{
	toml_array_t *array;
	int array_len;
	int i;
	const char *raw;
	struct string_array *result = _result;
	int error;

	/* Remove the previous value (usually the default). */
	opt->type->free(_result);

	array = toml_array_in(toml, opt->name);
	if (array == NULL)
		return pr_err("TOML array '%s' was not found.", opt->name);
	array_len = toml_array_nelem(array);

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
free_string_array(void *_array)
{
	struct string_array *array = _array;
	size_t i;

	for (i = 0; i < array->length; i++)
		free(array->array[i]);
	free(array->array);

	array->array = NULL;
	array->length = 0;
}

const struct global_type gt_string_array = {
	.has_arg = required_argument,
	.size = sizeof(char *const *),
	.print = print_string_array,
	.parse.toml = parse_toml_string_array,
	.free = free_string_array,
	.arg_doc = "<sequence of strings>",
};
