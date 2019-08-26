#include "incidence/incidence.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include "common.h"
#include "json_parser.h"
#include "log.h"
#include "data_structure/common.h"

struct incidence {
	const enum incidence_id id;
	char const *const name;
	char const *const description;
	const enum incidence_action default_action;
	enum incidence_action action;
};

static struct incidence incidences[__INID_MAX] = {
	{
		INID_HASHALG_HAS_PARAMS,
		"incid-hashalg-has-params",
		"Signed Object's hash algorithm has NULL object as parameters",
		INAC_IGNORE,
	},
};

static int
name2id(char const *name, enum incidence_id *id)
{
	array_index i;

	for (i = 0; i < __INID_MAX; i++) {
		if (strcmp(name, incidences[i].name) == 0) {
			*id = i;
			return 0;
		}
	}

	return pr_err("Unknown incidence name: %s", name);
}

static char const *
action2str(enum incidence_action action)
{
	switch (action) {
	case INAC_IGNORE:
		return "ignore";
	case INAC_WARN:
		return "warn";
	case INAC_ERROR:
		return "error";
	}

	return "unknown";
}

static int
init_action(json_t *json)
{
	enum incidence_id id;
	char const *name;
	char const *action_str;
	enum incidence_action action;
	int error;

	error = json_get_string(json, "name", &name);
	if (error)
		return error;
	error = name2id(name, &id);
	if (error)
		return error;
	error = json_get_string(json, "action", &action_str);
	if (error)
		return error;

	if (strcmp("ignore", action_str) == 0)
		action = INAC_IGNORE;
	else if (strcmp("warn", action_str) == 0)
		action = INAC_WARN;
	else if (strcmp("error", action_str) == 0)
		action = INAC_ERROR;
	else
		return pr_err("Unknown incidence action: '%s'", action_str);

	incidences[id].action = action;
	return 0;
}

/**
 * Concurrent inits are allowed.
 */
int
incidence_init(void)
{
	array_index i;

	/* Make sure the programmer didn't desync the id enum and the array. */
	assert(__INID_MAX == ARRAY_LEN(incidences));
	for (i = 0; i < __INID_MAX; i++) {
		assert(i == incidences[i].id);
		/* Also init. */
		incidences[i].action = incidences[i].default_action;
	}

	return 0;
}

/**
 * Concurrent calls to this function are allowed.
 */
int
incidence_update(json_t *json)
{
	array_index i;
	json_t *child;
	int error;

	if (!json_is_array(json))
		return pr_err("The incidences JSON element is supposed to be an array.");

	json_array_foreach(json, i, child) {
		error = init_action(child);
		if (error)
			return error;
	}

	return 0;
}

void
incidence_print(void)
{
	array_index i;

	pr_info("Custom incidences:");
	pr_indent_add();

	for (i = 0; i < __INID_MAX; i++) {
		pr_info("%s (%s): %s", incidences[i].name,
		    incidences[i].description,
		    action2str(incidences[i].action));
	}

	pr_indent_rm();
}

enum incidence_action
incidence_get_action(enum incidence_id id)
{
	return incidences[id].action;
}
