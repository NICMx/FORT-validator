#include "config/init_tals.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include "log.h"

#define JSON_MEMBER_URL "url"
#define JSON_MEMBER_MESSAGE "accept-message"
//
//struct init_location {
//	char *url;
//	char *accept_message;
//	SLIST_ENTRY(init_location) next;
//};
//
//SLIST_HEAD(init_locations, init_location);

static int
init_location_create(char const *url, struct init_location **result)
{
	struct init_location *tmp;

	tmp = malloc(sizeof(struct init_location));
	if (tmp == NULL)
		return pr_enomem();

	tmp->url = strdup(url);
	if (tmp->url == NULL) {
		free(tmp);
		return pr_enomem();
	}

	tmp->accept_message = NULL;

	*result = tmp;
	return 0;
}

static void
init_location_destroy(struct init_location *location)
{
	if (location->accept_message != NULL)
		free(location->accept_message);
	free(location->url);
	free(location);
}

void
init_locations_cleanup(struct init_locations *locations)
{
	struct init_location *tmp;

	while (!SLIST_EMPTY(locations)) {
		tmp = locations->slh_first;
		SLIST_REMOVE_HEAD(locations, next);
		init_location_destroy(tmp);
	}
}

void
__init_locations_cleanup(void *arg)
{
	init_locations_cleanup(arg);
}

static int
init_locations_add_n_msg(struct init_locations *locations, char const *url)
{
	struct init_location *tmp;
	int error;

	tmp = NULL;
	error = init_location_create(url, &tmp);
	if (error)
		return error;

	SLIST_INSERT_HEAD(locations, tmp, next);
	return 0;
}

static int
init_locations_add_w_msg(struct init_locations *locations, char const *url,
    char const *message)
{
	struct init_location *tmp;
	int error;

	tmp = NULL;
	error = init_location_create(url, &tmp);
	if (error)
		return error;

	tmp->accept_message = strdup(message);
	if (tmp->accept_message == NULL) {
		init_location_destroy(tmp);
		return pr_enomem();
	}

	SLIST_INSERT_HEAD(locations, tmp, next);
	return 0;
}

int
init_locations_init(struct init_locations *locations,
    char const *const *non_message, size_t non_message_len,
    char const *const *with_message, size_t with_message_len)
{
	size_t i;
	int error;

	SLIST_INIT(locations);

	for (i = 0; i < non_message_len; i++) {
		error = init_locations_add_n_msg(locations, non_message[i]);
		if (error)
			goto cleanup;
	}

	for (i = 0; i < with_message_len; i+=2) {
		error = init_locations_add_w_msg(locations, with_message[i],
		    with_message[i + 1]);
		if (error)
			goto cleanup;
	}

	return 0;
cleanup:
	init_locations_cleanup(locations);
	return error;
}

int
init_locations_foreach(struct init_locations *locations,
    init_locations_foreach_cb cb, void *arg)
{
	struct init_location *ptr;
	int error;

	SLIST_FOREACH(ptr, locations, next) {
		// FIXME TEST
		pr_op_err("--> foreach = %s, '%s'", ptr->url,
		    (ptr->accept_message == NULL) ? "NULL" : ptr->accept_message);

		error = cb(ptr->url, ptr->accept_message, arg);
		if (error)
			return error;
	}

	return 0;
}

static int
parse_location(char const *name, size_t pos, json_t *json, char const **url,
    char const **message)
{
	json_t *member;

	member = json_object_get(json, JSON_MEMBER_URL);
	if (member == NULL)
		return pr_op_err("'%s' array element #%zu requires the member '%s'.",
		    name, pos, JSON_MEMBER_URL);

	if (!json_is_string(member))
		return pr_op_err("'%s' array element #%zu '%s' member must be a string",
		    name, pos, JSON_MEMBER_URL);

	*url = json_string_value(member);

	/* Optional */
	member = json_object_get(json, JSON_MEMBER_MESSAGE);
	if (member == NULL) {
		*message = NULL;
		return 0;
	}

	if (!json_is_string(member))
		return pr_op_err("'%s' array element #%zu '%s' member must be a string",
		    name, pos, JSON_MEMBER_MESSAGE);

	*message = json_string_value(member);

	return 0;
}

static int
init_tals_parse_json(struct option_field const *opt, json_t *json, void *result)
{
	struct init_locations *ptr;
	json_t *elem;
	size_t len;
	size_t i;
	char const *url;
	char const *message;
	int error;

	if (!json_is_array(json)) {
		return pr_op_err("The '%s' element is not a JSON array",
		    opt->name);
	}

	len = json_array_size(json);

	if (len == 0) {
		/* Cleanup default value */
		init_locations_cleanup(result);
		return 0;
	}

	ptr = result;

	/* Remove the previous value (usually the default). */
	init_locations_cleanup(ptr);

	for (i = 0; i < len; i++) {
		elem = json_array_get(json, i);
		if (!json_is_object(elem))
			return pr_op_err("'%s' array element #%zu is not an object",
			    opt->name, i);

		url = NULL;
		message = NULL;
		error = parse_location(opt->name, i, elem, &url, &message);
		if (error)
			goto cleanup;

		if (message == NULL)
			error = init_locations_add_n_msg(ptr, url);
		else
			error = init_locations_add_w_msg(ptr, url, message);

		if (error)
			goto cleanup;
	}
	return 0;
cleanup:
	init_locations_cleanup(ptr);
	return error;
}

const struct global_type gt_init_tals_locations = {
	.print = NULL,
	.parse.json = init_tals_parse_json,
	.free = __init_locations_cleanup,
};
