#include "json_parser.h"

#include <err.h>
#include <errno.h>

/*
 * Try to get member @name from @parent as a char const *. On success, set
 * @result with the members value.
 *
 * Returns 0 on success, -ENOENT if the @name doesn't exists, -EINVAL if the
 * member isn't a JSON integer.
 */
int
json_get_string(json_t *parent, char const *name, char const **result)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL) {
		*result = NULL;
		return -ENOENT;
	}

	if (!json_is_string(child)) {
		warnx("The '%s' element is not a JSON string.", name);
		*result = NULL;
		return -EINVAL;
	}

	*result = json_string_value(child);
	return 0;
}

/*
 * Try to get member @name from @parent as a json_int_t. On success, set
 * @result with the members value.
 *
 * Returns 0 on success, -ENOENT if the @name doesn't exists, -EINVAL if the
 * member isn't a JSON integer.
 */
int
json_get_int(json_t *parent, char const *name, json_int_t *result)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL)
		return -ENOENT;

	if (!json_is_integer(child)) {
		warnx("The '%s' element is not a JSON integer.", name);
		return -EINVAL;
	}

	*result = json_integer_value(child);
	return 0;
}

json_t *
json_get_array(json_t *parent, char const *name)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL) {
		return NULL;
	}

	if (!json_is_array(child)) {
		warnx("The '%s' element is not a JSON array.", name);
		return NULL;
	}

	return child;
}

json_t *
json_get_object(json_t *parent, char const *name)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL)
		return NULL;

	if (!json_is_object(child)) {
		warnx("The '%s' element is not a JSON object.", name);
		return NULL;
	}

	return child;
}
