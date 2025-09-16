#include "config/curl_offset.h"

#include <curl/curl.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>

#include "log.h"

static void
print_curloff(struct option_field const *field, void *value)
{
	pr_op_info("%s: %" CURL_FORMAT_CURL_OFF_T,
	    field->name, *((curl_off_t *) value));
}

static int
parse_argv_curloff(struct option_field const *field, char const *str,
    void *result)
{
	char *tmp;
	long long parsed;
	int error;

	if (field->type->has_arg != required_argument || str == NULL ||
		    strlen(str) == 0) {
		return pr_op_err("Integer options ('%s' in this case) require an argument.",
		    field->name);
	}

	errno = 0;
	parsed = strtoll(str, &tmp, 10);
	error = errno;
	if (error || *tmp != '\0') {
		if (!error)
			error = -EINVAL;
		pr_op_err("Value '%s' at '%s' is not an integer: %s",
		    str, field->name, strerror(abs(error)));
		return error;
	}

	if (parsed < 0)
		return pr_op_err("Value of '%s' is negative.", field->name);

	*((curl_off_t *) result) = parsed;
	return 0;
}

static int
parse_json_curloff(struct option_field const *opt, json_t *json, void *result)
{
	json_int_t value;

	if (!json_is_integer(json))
		return pr_op_err("The '%s' element is not a JSON integer.",
		    opt->name);

	value = json_integer_value(json);

	if (value < 0)
		return pr_op_err("Value of '%s' is negative.", opt->name);

	*((curl_off_t *) result) = value;
	return 0;
}

const struct global_type gt_curl_offset = {
	.has_arg = required_argument,
	.size = sizeof(curl_off_t),
	.print = print_curloff,
	.parse.argv = parse_argv_curloff,
	.parse.json = parse_json_curloff,
	.arg_doc = "<unsigned integer>",
};
