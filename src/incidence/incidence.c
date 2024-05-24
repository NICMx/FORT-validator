#include "incidence/incidence.h"

#include <assert.h>

#include "common.h"
#include "data_structure/common.h"
#include "json_util.h"
#include "log.h"

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
	{
		INID_OBJ_NOT_DER,
		"incid-obj-not-der-encoded",
		"Object isn't DER encoded",
		INAC_IGNORE,
	},
	{
		INID_MFT_FILE_NOT_FOUND,
		"incid-file-at-mft-not-found",
		"File listed at manifest doesn't exist",
		INAC_ERROR,
	},
	{
		INID_MFT_FILE_HASH_NOT_MATCH,
		"incid-file-at-mft-hash-not-match",
		"File hash listed at manifest doesn't match the actual file hash",
		INAC_ERROR,
	},
	{
		INID_MFT_STALE,
		"incid-mft-stale",
		"The current time is after the nextUpdate field at the manifest",
		INAC_ERROR,
	},
	{
		INID_CRL_STALE,
		"incid-crl-stale",
		"The current time is after the nextUpdate field at the CRL",
		INAC_ERROR,
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

	return pr_op_err("Unknown incidence name: %s", name);
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

	id = __INID_MAX;
	error = json_get_str(json, "name", &name);
	if (error < 0)
		return error;
	if (error > 0)
		return pr_op_err("Incidence is missing the 'name' tag.");
	error = name2id(name, &id);
	if (error)
		return error;
	error = json_get_str(json, "action", &action_str);
	if (error < 0)
		return error;
	if (error > 0)
		return pr_op_err("Incidence '%s' is missing the 'action' tag.",
		    name);

	if (strcmp("ignore", action_str) == 0)
		action = INAC_IGNORE;
	else if (strcmp("warn", action_str) == 0)
		action = INAC_WARN;
	else if (strcmp("error", action_str) == 0)
		action = INAC_ERROR;
	else
		return pr_op_err("Unknown incidence action: '%s'", action_str);

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
		return pr_op_err("The incidences JSON element is supposed to be an array.");

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

	pr_op_info("Custom incidences:");

	for (i = 0; i < __INID_MAX; i++) {
		pr_op_info("  %s (%s): %s", incidences[i].name,
		    incidences[i].description,
		    action2str(incidences[i].action));
	}
}

enum incidence_action
incidence_get_action(enum incidence_id id)
{
	return incidences[id].action;
}
