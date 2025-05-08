#include "json_util.h"

#include <errno.h>
#include <limits.h>
#include <time.h>

#include "alloc.h"
#include "common.h"
#include "log.h"

int
json_get_str(json_t *parent, char const *name, char const **result)
{
	json_t *child;

	*result = NULL;

	child = json_object_get(parent, name);
	if (child == NULL)
		return ENOENT;

	if (!json_is_string(child))
		return pr_op_err("Tag '%s' is not a JSON string.", name);

	*result = json_string_value(child);
	return 0;
}

/* @result needs cleanup. */
int
json_get_uri(json_t *parent, char const *name, struct uri *result)
{
	char const *str;
	int error;
	error_msg errmsg;

	memset(result, 0, sizeof(*result));

	error = json_get_str(parent, name, &str);
	if (error)
		return error;
	errmsg = uri_init(result, str);
	if (errmsg)
		return pr_op_err("'%s' does not seem to be a URI: %s",
		    str, errmsg);

	return 0;
}

static int
json_get_int_t(json_t *parent, char const *name, json_int_t *result)
{
	json_t *child;

	*result = 0;

	child = json_object_get(parent, name);
	if (child == NULL)
		return ENOENT;

	if (!json_is_integer(child))
		return pr_op_err("Tag '%s' is not a JSON integer.", name);

	*result = json_integer_value(child);
	return 0;
}

int
json_get_int(json_t *parent, char const *name, int *result)
{
	json_int_t json_int;
	int error;

	*result = 0;

	error = json_get_int_t(parent, name, &json_int);
	if (error)
		return error;
	if (json_int < INT_MIN || INT_MAX < json_int)
		return pr_op_err("Tag '%s' (%" JSON_INTEGER_FORMAT
		    ") is out of range [%d, %d].",
		    name, json_int, INT_MIN, INT_MAX);

	*result = json_int;
	return 0;
}

int
json_get_u32(json_t *parent, char const *name, uint32_t *result)
{
	json_int_t json_int;
	int error;

	*result = 0;

	error = json_get_int_t(parent, name, &json_int);
	if (error)
		return error;
	if (json_int < 0 || UINT32_MAX < json_int)
		return pr_op_err("Tag '%s' (%" JSON_INTEGER_FORMAT
		    ") is out of range [0, %u].",
		    name, json_int, UINT32_MAX);

	*result = json_int;
	return 0;
}

int
json_get_ulong(json_t *parent, char const *name, unsigned long *result)
{
	json_int_t json_int;
	int error;

	*result = 0;

	error = json_get_int_t(parent, name, &json_int);
	if (error)
		return error;
	if (json_int < 0 || ULONG_MAX < json_int)
		return pr_op_err("Tag '%s' (%" JSON_INTEGER_FORMAT
		    ") is out of range [0, %lu].",
		    name, json_int, ULONG_MAX);

	*result = json_int;
	return 0;
}

int
json_get_bigint(json_t *parent, char const *name, INTEGER_t *result)
{
	char const *str;
	int error;

	error = json_get_str(parent, name, &str);
	if (error)
		return error;

	error = asn_str2INTEGER(str, result);
	if (error)
		pr_op_err("Tag '%s' (%s) cannot be parsed into an integer: %s",
		    name, str, strerror(error));

	return error;
}

int
json_get_ts(json_t *parent, char const *name, time_t *result)
{
	char const *str;
	int error;

	error = json_get_str(parent, name, &str);
	if (error)
		return error;

	return str2time(str, result);
}

int
json_get_array(json_t *parent, char const *name, json_t **array)
{
	json_t *child;

	*array = NULL;

	child = json_object_get(parent, name);
	if (child == NULL)
		return ENOENT;

	if (!json_is_array(child))
		return pr_op_err("Tag '%s' is not a JSON array.", name);

	*array = child;
	return 0;
}

int
json_get_object(json_t *parent, char const *name, json_t **obj)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL) {
		*obj = NULL;
		return ENOENT;
	}

	if (!json_is_object(child)) {
		*obj = NULL;
		return pr_op_err("Tag '%s' is not a JSON object.", name);
	}

	*obj = child;
	return 0;
}

/*
 * Any unknown members should be treated as errors, RFC8416 3.1:
 * "JSON members that are not defined here MUST NOT be used in SLURM
 * files. An RP MUST consider any deviations from the specifications to
 * be errors."
 */
bool
json_valid_members_count(json_t *object, size_t expected_size)
{
	return json_object_size(object) == expected_size;
}

int
json_add_int(json_t *parent, char const *name, int value)
{
	if (json_object_set_new(parent, name, json_integer(value)))
		return pr_op_err(
		    "Cannot convert %s '%d' to json; unknown cause.",
		    name, value
		);

	return 0;
}

int
json_add_ulong(json_t *parent, char const *name, unsigned long value)
{
	if (json_object_set_new(parent, name, json_integer(value)))
		return pr_op_err(
		    "Cannot convert %s '%lu' to json; unknown cause.",
		    name, value
		);

	return 0;
}

int
json_add_bigint(json_t *parent, char const *name, INTEGER_t *value)
{
	char *str;
	int error;

	str = asn_INTEGER2str(value);
	if (!str)
		return pr_op_err("Cannot convert %s to string.", name);

	error = json_add_str(parent, name, str);

	free(str);
	return error;
}

int
json_add_str(json_t *parent, char const *name, char const *value)
{
	if (json_object_set_new(parent, name, json_string(value)))
		return pr_op_err(
		    "Cannot convert %s '%s' to json; unknown cause.",
		    name, value
		);

	return 0;
}

int
json_add_strn(json_t *parent, char const *name, char const *value, size_t len)
{
	if (json_object_set_new(parent, name, json_stringn(value, len)))
		return pr_op_err(
		    "Cannot convert %s '%.*s' to json; unknown cause.",
		    name, (int)len, value
		);

	return 0;
}

int
json_add_ts(json_t *parent, char const *name, time_t value)
{
	char str[FORT_TS_LEN];
	int error;

	error = time2str(value, str);
	if (error) {
		pr_op_err("Cannot convert timestamp '%s' to json: %s",
		    name, strerror(error));
		return error;
	}

	if (json_object_set_new(parent, name, json_string(str)))
		return pr_op_err(
		    "Cannot convert timestamp '%s' to json; unknown cause.",
		    name
		);

	return 0;
}

#define OOM_PFX " Likely out of memory (but there is no contract)."

json_t *
json_obj_new(void)
{
	json_t *json = json_object();
	if (json == NULL)
		pr_op_err_st("Cannot create JSON object." OOM_PFX);
	return json;
}

json_t *
json_array_new(void)
{
	json_t *json = json_array();
	if (json == NULL)
		pr_op_err_st("Cannot create JSON array." OOM_PFX);
	return json;
}

json_t *
json_int_new(json_int_t value)
{
	json_t *json = json_integer(value);
	if (json == NULL)
		pr_op_err_st("Cannot create JSON integer '%lld'."
			     OOM_PFX, value);
	return json;
}

json_t *
json_str_new(const char *value)
{
	json_t *json = json_string(value);
	if (json == NULL)
		pr_op_err_st("Cannot create JSON string '%s'." OOM_PFX, value);
	return json;
}

json_t *
json_strn_new(const char *value, size_t len)
{
	json_t *json = json_stringn(value, len);
	if (json == NULL)
		pr_op_err_st("Cannot create JSON string '%.*s'."
			     OOM_PFX, (int)len, value);
	return json;
}

int
json_object_add(json_t *parent, char const *name, json_t *value)
{
	int res;

	if (value == NULL)
		return -1; /* Already messaged */

	res = json_object_set_new(parent, name, value);
	if (res == -1)
		pr_op_err_st("Cannot add JSON '%s' to parent; unknown error.",
			     name);
	return res;
}

int
json_array_add(json_t *array, json_t *node)
{
	int res;

	if (node == NULL)
		return -1; /* Already messaged */

	res = json_array_append_new(array, node);
	if (res == -1)
		pr_op_err_st("Cannot add JSON node to array; unknown error.");
	return res;
}
