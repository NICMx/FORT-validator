#include "toml_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <toml.h>

#include "config.h"
#include "file.h"
#include "log.h"
#include "uri.h"

static int
toml_to_config(struct toml_table_t *root)
{
	struct group_fields const *groups;
	struct group_fields const *group;
	struct option_field const *option;
	struct toml_table_t *table;
	const char *value;
	int error;

	get_group_fields(&groups);

	for (group = groups; group->name != NULL; group++) {
		table = toml_table_in(root, group->name);
		if (table == NULL)
			continue;

		for (option = group->options; option->id != 0; option++) {
			if (option->availability == 0
			    || (option->availability & AVAILABILITY_TOML)) {
				value = toml_raw_in(table, option->name);
				if (value == NULL)
					continue;
				error = parse_option(option, value);
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
	struct rpki_uri uri;
	char errbuf[200];
	int error;

	uri.global = config_file;
	uri.global_len = strlen(config_file);
	uri.local = config_file;

	error = file_open(&uri, &file, &stat);
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
