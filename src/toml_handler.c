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


static void
print_config(struct rpki_config *config)
{
	pr_debug("Program configuration");
	pr_debug_add("{");
	pr_debug("%s: %s", "local_repository", config->local_repository);
	pr_debug("%s: %s", "tal.file", config->tal);
	pr_debug("%s: %s", "enable_rsync",
	    config->enable_rsync ? "true" : "false");
	pr_debug("%s: %s", "tal.shuffle_uris",
	    config->shuffle_uris ? "true" : "false");
	pr_debug("%s: %u", "tal.maximum-certificate-depth",
		    config->maximum_certificate_depth);
	pr_debug_rm("}");
}

static int
iterate_fields(struct toml_table_t *table, struct rpki_config *config,
    struct option_field *fields, unsigned int field_len)
{
	struct option_field *field;
	const char *result;
	char *str;
	int i, error, missing_param;

	missing_param = 0;

	for (i = 0; i < field_len; i++) {
		field = &(fields[i]);
		result = toml_raw_in(table, field->name);
		if (result == 0) {
			if (field->required) {
				printf("Required parameter is missing '%s'\n",
				    field->name);
				missing_param |= -ENOENT;
			}
			continue;
		}

		str = (char *) result;
		if (field->type->id == GTI_STRING) {
			error = toml_rtos(result, &str);
			if (error)
				return pr_err("Bad value in '%s'",
				    field->name);
		}

		error = handle_option(config, field, str);
		if (error)
			return error;

	}

	if (missing_param)
		return missing_param;
	return error;
}

static int
handle_tal_table(struct toml_table_t *tal, struct rpki_config *config)
{
	struct option_field *tal_fields;
	unsigned int tal_len;

	get_tal_fields(&tal_fields, &tal_len);

	return iterate_fields(tal, config, tal_fields, tal_len);
}

static int
toml_to_config(struct toml_table_t *root, struct rpki_config *config)
{
	struct option_field *globals;
	struct toml_table_t *tal;
	int error;
	unsigned int global_len;


	get_global_fields(&globals, &global_len);
	error = iterate_fields(root, config, globals, global_len);
	if (error)
		return error;

	tal = toml_table_in(root, "tal");
	if (tal != 0)
		error = handle_tal_table(tal, config);
	else
		return pr_err("Required table '%s' is missing.", "tal");

	return error;
}

int
set_config_from_file(char *config_file, struct rpki_config *config)
{
	struct file_contents fc;
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

	error = file_load(&uri, &fc);
	if (error)
		goto end; /* Error msg already printed. */

	root = toml_parse((char *) fc.buffer, errbuf, sizeof(errbuf));
	file_free(&fc);

	if (root == NULL) {
		error = pr_err("Error while parsing configuration file: %s",
		    errbuf);
		goto end;
	}

	error = toml_to_config(root, config);

	toml_free(root);

	print_config(config);

end:
	return error;
}
