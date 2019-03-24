#include "config/out_file.h"

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "config/str.h"

static void
__free_out_file(struct config_out_file *file)
{
	if (file->fd != NULL) {
		fclose(file->fd);
		file->fd = NULL;
	}

	free(file->file_name);
	file->file_name = NULL;
}

static void
print_out_file(struct group_fields const *group,
    struct option_field const *field, void *value)
{
	struct config_out_file *file = value;
	pr_info("%s.%s: %s", group->name, field->name, file->file_name);
}

static int
parse_argv_out_file(struct option_field const *field, char const *file_name,
    void *_result)
{
	struct config_out_file *file = _result;
	int error;

	__free_out_file(file);

	file->file_name = strdup(file_name);
	if (file->file_name == NULL)
		return pr_enomem();

	file->fd = fopen(file_name, "w");
	if (file->fd == NULL) {
		error = errno;
		free(file->file_name);
		file->file_name = NULL;
		return pr_errno(error, "Could not open file '%s'", file_name);
	}

	return 0;
}

static int
parse_toml_out_file(struct option_field const *opt, struct toml_table_t *toml,
    void *_result)
{
	char *file_name;
	int error;

	error = parse_toml_string(toml, opt->name, &file_name);
	if (error)
		return error;
	if (file_name == NULL)
		return 0;

	error = parse_argv_out_file(opt, file_name, _result);

	free(file_name);
	return error;
}

static void
free_out_file(void *file)
{
	__free_out_file(file);
}

const struct global_type gt_out_file = {
	.has_arg = required_argument,
	.size = sizeof(struct config_out_file),
	.print = print_out_file,
	.parse.argv = parse_argv_out_file,
	.parse.toml = parse_toml_out_file,
	.free = free_out_file,
	.arg_doc = "<file>",
};
