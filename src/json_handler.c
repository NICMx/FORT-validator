#include "json_handler.h"

#include <errno.h>
#include <string.h>

#include "alloc.h"
#include "config.h"
#include "log.h"

static json_t *
find_json(struct json_t *root, char const *full_name)
{
	struct {
		char *opt_name; /* full token sequence string */
		char *token; /* current token */
		char *saveptr; /* state needed by strtok_r */
	} strtok;
	struct json_t *node;

	/* strtok_r() needs a non-const string */
	strtok.opt_name = pstrdup(full_name);

	node = root;
	strtok.token = strtok_r(strtok.opt_name, ".", &strtok.saveptr);

	while (node != NULL && strtok.token != NULL) {
		node = json_object_get(node, strtok.token);
		strtok.token = strtok_r(NULL, ".", &strtok.saveptr);
	}

	free(strtok.opt_name);
	return node;
}

static int
json_to_config(struct json_t *root)
{
	struct option_field const *opt;
	struct json_t *child = NULL;
	int error;

	FOREACH_OPTION(get_option_metadatas(), opt, AVAILABILITY_JSON) {
		child = find_json(root, opt->name);
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
		pr_op_err("JSON error on line %d, column %d: %s",
		    json_error.line, json_error.column, json_error.text);
		return -ENOENT;
	}

	error = json_to_config(root);

	json_decref(root);
	return error;
}
