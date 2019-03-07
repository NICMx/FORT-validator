#include "toml_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <toml.h>

#include "config.h"
#include "file.h"
#include "log.h"
#include "uri.h"
#include "config/types.h"

static int
toml_to_config(struct toml_table_t *root)
{
	struct group_fields const *groups;
	struct group_fields const *group;
	struct option_field const *option;
	struct toml_table_t *table;
	int error;

	get_group_fields(&groups);

	for (group = groups; group->name != NULL; group++) {
		table = toml_table_in(root, group->name);
		if (table == NULL)
			continue;

		for (option = group->options; option->id != 0; option++) {
			if (option->availability == 0
			    || (option->availability & AVAILABILITY_TOML)) {
				error = option->type->parse.toml(option, table,
				    get_rpki_config_field(option));
				if (error)
					return error;
			}
		}
	}

	return error;
}

int
set_config_from_file(char *config_file)
{
	FILE *file;
	struct stat stat;
	struct toml_table_t *root;
	char errbuf[200];
	int error;

	error = file_open(config_file, &file, &stat);
	if (error)
		return error; /* Error msg already printed. */

	root = toml_parse_file(file, errbuf, sizeof(errbuf));
	file_close(file);

	if (root == NULL) {
		return pr_err("Error while parsing configuration file: %s",
		    errbuf);
	}

	error = toml_to_config(root);

	toml_free(root);

	return error;
}
