#include "config.h"

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
	pr_debug("%s: %s", "local_repository",
	    config->local_repository);
	pr_debug("%s: %s", "tal.file", config->tal);
	pr_debug("%s: %s", "enable_rsync",
	    config->enable_rsync ? "true" : "false");
	pr_debug("%s: %s", "tal.shuffle_uris",
	    config->shuffle_uris ? "true" : "false");
	pr_debug_rm("}");
}

static int
handle_tal_table(struct toml_table_t *tal, struct rpki_config *config)
{
	const char *result;
	int error, bool_result;

	result = toml_raw_in(tal, "file");
	if (result != 0) {
		pr_debug("tal.file raw string %s", result);
		error = toml_rtos(result, &config->tal);
		if (error)
			return pr_err("Bad value in '%s'", "file");
	}

	result = toml_raw_in(tal, "shuffle_uris");
	if (result != 0) {
		pr_debug("Boolean %s", result);

		error = toml_rtob(result, &bool_result);
		if (error)
			return pr_err("Bad value in '%s'", "shuffle_uris");
		config->shuffle_uris = bool_result;
	}

	return 0;
}

static int
toml_to_config(struct toml_table_t *root, struct rpki_config *config)
{
	struct toml_table_t *tal;
	const char *result;
	int error, bool_result;

	result = toml_raw_in(root, "local_repository");
	if (result != 0) {
		error = toml_rtos(result, &config->local_repository);
		if (error)
			return pr_err("Bad value in '%s'", "local_repository");
	}

	result = toml_raw_in(root, "enable_rsync");
	if (result != 0) {
		error = toml_rtob(result, &bool_result);
		if (error)
			return pr_err("Bad value in '%s'", "enable_rsync");
		config->enable_rsync = bool_result;
	}

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
