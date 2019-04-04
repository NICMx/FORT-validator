#include "json_handler.h"

#include <errno.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "config/types.h"

int
find_json(struct json_t *root, char const *full_name, json_t **result)
{
	struct {
		char *opt_name; /* full token sequence string */
		char *token; /* current token */
		char *saveptr; /* state needed by strtok_r */
	} strtok;
	struct json_t *node;

	/* strtok_r() needs a non-const string */
	strtok.opt_name = strdup(full_name);
	if (strtok.opt_name == NULL)
		return pr_enomem();

	node = root;
	strtok.token = strtok_r(strtok.opt_name, ".", &strtok.saveptr);

	while (node != NULL && strtok.token != NULL) {
		node = json_object_get(node, strtok.token);
		strtok.token = strtok_r(NULL, ".", &strtok.saveptr);
	}

	free(strtok.opt_name);
	*result = node;
	return 0;
}

static int
json_to_config(struct json_t *root)
{
	struct option_field const *opt;
	struct json_t *child;
	int error;

	FOREACH_OPTION(get_option_metadatas(), opt, AVAILABILITY_JSON) {
		error = find_json(root, opt->name, &child);
		if (error)
			return error;
		if (child == NULL)
			continue;

		error = opt->type->parse.json(opt, child,
		    get_rpki_config_field(opt));
		if (error)
			return error;
	}

	return 0;
}

int
set_config_from_file(char *file)
{
	json_t *root;
	json_error_t json_error;
	int error;

	root = json_load_file(file, JSON_REJECT_DUPLICATES, &json_error);
	if (root == NULL) {
		pr_err("JSON error on line %d, column %d: %s",
		    json_error.line, json_error.column, json_error.text);
		return -ENOENT;
	}

	error = json_to_config(root);

	json_decref(root);
	return error;
}
