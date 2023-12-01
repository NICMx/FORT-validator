#include "json_util.h"

#include <errno.h>
#include <limits.h>
#include <time.h>
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

int
json_get_bool(json_t *parent, char const *name, bool *result)
{
	json_t *child;

	*result = false;

	child = json_object_get(parent, name);
	if (child == NULL)
		return ENOENT;

	if (!json_is_boolean(child))
		return pr_op_err("Tag '%s' is not a JSON boolean.", name);

	*result = json_boolean_value(child);
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
json_get_ts(json_t *parent, char const *name, time_t *result)
{
	char const *str, *consumed;
	struct tm tm;
	time_t time;
	int error;

	*result = 0;

	error = json_get_str(parent, name, &str);
	if (error)
		return error;

	memset(&tm, 0, sizeof(tm));
	consumed = strptime(str, "%FT%T%z", &tm);
	if (consumed == NULL || (*consumed) != 0)
		return pr_op_err("String '%s' does not appear to be a timestamp.",
		    str);
	time = mktime(&tm);
	if (time == ((time_t) -1)) {
		error = errno;
		return pr_op_err("String '%s' does not appear to be a timestamp: %s",
		    str, strerror(error));
	}

	*result = time;
	return 0;
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

	*obj = NULL;

	child = json_object_get(parent, name);
	if (child == NULL)
		return ENOENT;

	if (!json_is_object(child))
		return pr_op_err("Tag '%s' is not a JSON object.", name);

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
json_add_bool(json_t *parent, char const *name, bool value)
{
	if (json_object_set_new(parent, name, json_boolean(value)))
		return pr_op_err(
		    "Cannot convert %s '%u' to json; unknown cause.",
		    name, value
		);

	return 0;
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
json_add_str(json_t *parent, char const *name, char const *value)
{
	if (json_object_set_new(parent, name, json_string(value)))
		return pr_op_err(
		    "Cannot convert %s '%s' to json; unknown cause.",
		    name, value
		);

	return 0;
}

static int
tt2json(time_t tt, json_t **result)
{
	char str[32];
	struct tm tmbuffer, *tm;

	memset(&tmbuffer, 0, sizeof(tmbuffer));
	tm = localtime_r(&tt, &tmbuffer);
	if (tm == NULL)
		return errno;
	if (strftime(str, sizeof(str) - 1, "%FT%T%z", tm) == 0)
		return ENOSPC;

	*result = json_string(str);
	return 0;
}

int
json_add_date(json_t *parent, char const *name, time_t value)
{
	json_t *date = NULL;
	int error;

	error = tt2json(value, &date);
	if (error) {
		pr_op_err("Cannot convert timestamp '%s' to json: %s",
		    name, strerror(error));
		return error;
	}

	if (json_object_set_new(parent, name, date))
		return pr_op_err(
		    "Cannot convert timestamp '%s' to json; unknown cause.",
		    name
		);

	return 0;
}
