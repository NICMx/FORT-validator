#include "toml_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <toml.h>

#include "file.h"
#include "log.h"
#include "thread_var.h"
#include "uri.h"

static int
find_flag(struct args_flag *flags_handled, char *flag_to_find,
    struct args_flag **result)
{
	int cmp;
	*result = NULL;

	while(flags_handled->field != NULL) {
		cmp = strcmp(flags_handled->field->name, flag_to_find);
		if (cmp == 0) {
			*result = flags_handled;
			break;
		}
		flags_handled = flags_handled + 1;
	}

	if (*result == NULL)
		return pr_crit("Missing parameter %s.", flag_to_find);

	return 0;
}

static int
iterate_fields(struct toml_table_t *table, struct rpki_config *config,
    struct option_field *fields, struct args_flag *flags_handled)
{
	struct option_field *tmp_field;
	struct args_flag *tmp_arg;
	const char *result;
	char *str;
	int error;

	tmp_field = fields;
	while (tmp_field->name != NULL) {
		error = find_flag(flags_handled, tmp_field->name, &tmp_arg);
		if (error)
			return error; /* Error msg already printed. */
		if (tmp_arg->is_set) {
			tmp_field += 1;
			continue;
		}

		result = toml_raw_in(table, tmp_field->name);
		if (result == 0) {
			tmp_field += 1;
			continue;
		}

		str = (char *) result;
		if (tmp_field->type->id == GTI_STRING) {
			error = toml_rtos(result, &str);
			if (error)
				return pr_err("Bad value in '%s'",
				    tmp_field->name);
		}

		error = handle_option(config, tmp_field, str);
		if (error)
			return error;

		/* Free returned string from toml */
		if (tmp_field->type->id == GTI_STRING)
			free(str);

		tmp_arg->is_set = true;
		tmp_field += 1;
	}

	return error;
}

static int
toml_to_config(struct toml_table_t *root, struct rpki_config *config,
    struct args_flag *flags_handled)
{
	struct toml_table_t *toml_table;
	struct group_fields *group_fields;
	int error;

	get_group_fields(&group_fields);
	if (group_fields == NULL)
		return 0;

	error = iterate_fields(root, config, group_fields->options,
	    flags_handled);
	if (error)
		return error;
	group_fields += 1;

	while (group_fields->group_name != NULL) {
		toml_table = toml_table_in(root, group_fields->group_name);
		if (toml_table == 0) {
			group_fields += 1;
			continue;
		}
		error = iterate_fields(toml_table, config,
		    group_fields->options, flags_handled);
		if (error)
			return error;
		group_fields += 1;
	}

	return error;
}

int
set_config_from_file(char *config_file, struct rpki_config *config,
    struct args_flag *flags_handled)
{
	FILE *file;
	struct stat stat;
	struct toml_table_t *root;
	struct rpki_uri uri;
	char errbuf[200];
	int error;
	bool is_config_file;

	/* I think I'm not using this struct correctly but I need it to call
	 * some functions, so be careful using the struct rpki_uri here.
	 * Also no needs to be freed. */
	uri.global = config_file;
	uri.global_len = strlen(config_file);
	uri.local = config_file;

	is_config_file = uri_has_extension(&uri, ".ini");
	is_config_file |= uri_has_extension(&uri, ".toml");
	if (!is_config_file) {
		error = pr_err("Invalid Config file extension for file '%s'",
		    uri.local);
		goto end;
	}

	error = file_open(&uri, &file, &stat);
	if (error)
		goto end; /* Error msg already printed. */

	root = toml_parse_file(file, errbuf, sizeof(errbuf));
	file_close(file);

	if (root == NULL) {
		error = pr_err("Error while parsing configuration file: %s",
		    errbuf);
		goto end;
	}

	error = toml_to_config(root, config, flags_handled);

	toml_free(root);

end:
	return error;
}
