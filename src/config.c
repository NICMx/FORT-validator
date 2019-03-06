#include "config.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "common.h"
#include "log.h"
#include "toml_handler.h"

/**
 * Please note that this is actually two `for`s stacked together, so don't use
 * `break` nor `continue` to get out.
 */
#define FOREACH_OPTION(groups, grp, opt, type)			\
	for (grp = groups; grp->name != NULL; grp++)		\
		for (opt = grp->options; opt->id != 0; opt++)	\
			if ((opt->availability == 0) ||		\
			    (opt->availability & type))

struct config_out_file {
	FILE *fd;
	char *file_name;
};

/**
 * To add a member to this structure,
 *
 * 1. Add it.
 * 2. Add its metadata somewhere in @groups.
 * 3. Add default value to set_default_values().
 * 4. Create the getter.
 *
 * Assuming you don't need to create a data type, that should be all.
 */
struct rpki_config {
	/** TAL file name/location. */
	char *tal;
	/** Path of our local clone of the repository */
	char *local_repository;
	/** Synchronization (currently only RSYNC) download strategy. */
	enum sync_strategy sync_strategy;
	/**
	 * Shuffle uris in tal?
	 * (https://tools.ietf.org/html/rfc7730#section-3, last paragraphs)
	 */
	bool shuffle_uris;
	/**
	 * rfc6487#section-7.2, last paragraph.
	 * Prevents arbitrarily long paths and loops.
	 */
	unsigned int maximum_certificate_depth;

	struct {
		char *program;
		struct string_array args;
	} rsync;

	struct {
		/** Print ANSI color codes? */
		bool color;
		/** Format in which file names will be printed. */
		enum filename_format filename_format;
		/** Output stream where the valid ROAs will be dumped. */
		struct config_out_file roa_output;
	} output;
};

static void print_usage(FILE *, bool);

#define DECLARE_PRINT_FN(name)						\
	static void name(						\
	    struct group_fields const *,				\
	    struct option_field const *,				\
	    void *							\
	)
DECLARE_PRINT_FN(print_bool);
DECLARE_PRINT_FN(print_u_int);
DECLARE_PRINT_FN(print_string);
DECLARE_PRINT_FN(print_string_array);
DECLARE_PRINT_FN(print_sync_strategy);
DECLARE_PRINT_FN(print_filename_format);
DECLARE_PRINT_FN(print_out_file);

#define DECLARE_PARSE_ARGV_FN(name)					\
	static int name(						\
	    struct option_field const *,				\
	    char const *,						\
	    void *							\
	)
DECLARE_PARSE_ARGV_FN(parse_argv_bool);
DECLARE_PARSE_ARGV_FN(parse_argv_u_int);
DECLARE_PARSE_ARGV_FN(parse_argv_string);
DECLARE_PARSE_ARGV_FN(parse_argv_sync_strategy);
DECLARE_PARSE_ARGV_FN(parse_argv_filename_format);
DECLARE_PARSE_ARGV_FN(parse_argv_out_file);

#define DECLARE_PARSE_TOML_FN(name)					\
	static int name(						\
	    struct option_field const *,				\
	    struct toml_table_t *,					\
	    void *							\
	)
DECLARE_PARSE_TOML_FN(parse_toml_bool);
DECLARE_PARSE_TOML_FN(parse_toml_u_int);
DECLARE_PARSE_TOML_FN(parse_toml_string);
DECLARE_PARSE_TOML_FN(parse_toml_sync_strategy);
DECLARE_PARSE_TOML_FN(parse_toml_string_array);
DECLARE_PARSE_TOML_FN(parse_toml_filename_format);
DECLARE_PARSE_TOML_FN(parse_toml_out_file);

#define DECLARE_HANDLE_FN(name)						\
	static int name(						\
	    struct option_field const *,				\
	    char *							\
	)
DECLARE_HANDLE_FN(handle_help);
DECLARE_HANDLE_FN(handle_usage);
DECLARE_HANDLE_FN(handle_version);
DECLARE_HANDLE_FN(handle_toml);

#define DECLARE_FREE_FN(name) static void name(void *)
DECLARE_FREE_FN(free_string);
DECLARE_FREE_FN(free_string_array);
DECLARE_FREE_FN(free_out_file);

static char const *program_name;
static struct rpki_config rpki_config;

static const struct global_type gt_bool = {
	.has_arg = no_argument,
	.size = sizeof(bool),
	.print = print_bool,
	.parse.argv = parse_argv_bool,
	.parse.toml = parse_toml_bool,
	.arg_doc = "true|false",
};

static const struct global_type gt_u_int = {
	.has_arg = required_argument,
	.size = sizeof(unsigned int),
	.print = print_u_int,
	.parse.argv = parse_argv_u_int,
	.parse.toml = parse_toml_u_int,
	.arg_doc = "<unsigned integer>",
};

static const struct global_type gt_string = {
	.has_arg = required_argument,
	.size = sizeof(char *),
	.print = print_string,
	.parse.argv = parse_argv_string,
	.parse.toml = parse_toml_string,
	.free = free_string,
	.arg_doc = "<string>",
};

static const struct global_type gt_string_array = {
	.has_arg = required_argument,
	.size = sizeof(char *const *),
	.print = print_string_array,
	.parse.toml = parse_toml_string_array,
	.free = free_string_array,
	.arg_doc = "<sequence of strings>",
};

static const struct global_type gt_sync_strategy = {
	.has_arg = required_argument,
	.size = sizeof(enum sync_strategy),
	.print = print_sync_strategy,
	.parse.argv = parse_argv_sync_strategy,
	.parse.toml = parse_toml_sync_strategy,
	.arg_doc = SYNC_VALUE_OFF "|" SYNC_VALUE_STRICT "|" SYNC_VALUE_ROOT,
};

static const struct global_type gt_filename_format = {
	.has_arg = required_argument,
	.size = sizeof(enum filename_format),
	.print = print_filename_format,
	.parse.argv = parse_argv_filename_format,
	.parse.toml = parse_toml_filename_format,
	.arg_doc = FNF_VALUE_GLOBAL "|" FNF_VALUE_LOCAL "|" FNF_VALUE_NAME,
};

static const struct global_type gt_out_file = {
	.has_arg = required_argument,
	.size = sizeof(struct config_out_file),
	.print = print_out_file,
	.parse.argv = parse_argv_out_file,
	.parse.toml = parse_toml_out_file,
	.free = free_out_file,
	.arg_doc = "<file>",
};

/**
 * An option that takes no arguments, is not correlated to any rpki_config
 * fields, and is entirely managed by its handler function.
 */
static const struct global_type gt_callback = {
	.has_arg = no_argument,
};

static const struct option_field global_fields[] = {
	{
		.id = 'h',
		.name = "help",
		.type = &gt_callback,
		.handler = handle_help,
		.doc = "Give this help list",
		.availability = AVAILABILITY_GETOPT,
	}, {
		.id = 1000,
		.name = "usage",
		.type = &gt_callback,
		.handler = handle_usage,
		.doc = "Give a short usage message",
		.availability = AVAILABILITY_GETOPT,
	}, {
		.id = 'V',
		.name = "version",
		.type = &gt_callback,
		.handler = handle_version,
		.doc = "Print program version",
		.availability = AVAILABILITY_GETOPT,
	}, {
		.id = 'f',
		.name = "configuration-file",
		.type = &gt_string,
		.handler = handle_toml,
		.doc = "TOML file additional configuration will be read from",
		.arg_doc = "<file>",
		.availability = AVAILABILITY_GETOPT,
	}, {
		.id = 'r',
		.name = "local-repository",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, local_repository),
		.doc = "Directory where the repository local cache will be stored/read",
		.arg_doc = "<directory>",
	}, {
		.id = 1001,
		.name = "sync-strategy",
		.type = &gt_sync_strategy,
		.offset = offsetof(struct rpki_config, sync_strategy),
		.doc = "RSYNC download strategy",
	}, {
		.id = 1002,
		.name = "maximum-certificate-depth",
		.type = &gt_u_int,
		.offset = offsetof(struct rpki_config,
		    maximum_certificate_depth),
		.doc = "Maximum allowable certificate chain length",
		.min = 1,
		/**
		 * It cannot be UINT_MAX, because then the actual number will
		 * overflow and will never be bigger than this.
		 */
		.max = UINT_MAX - 1,
	},
	{ 0 },
};

static const struct option_field tal_fields[] = {
	{
		.id = 't',
		.name = "tal",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, tal),
		.doc = "Path to the TAL file",
		.arg_doc = "<file>",
	}, {
		.id = 2000,
		.name = "shuffle-uris",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, shuffle_uris),
		.doc = "Shuffle URIs in the TAL before accessing them",
	},
	{ 0 },
};

static const struct option_field rsync_fields[] = {
	{
		.id = 3000,
		.name = "program",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, rsync.program),
		.doc = "Name of the program needed to execute an RSYNC",
		.arg_doc = "<path to program>",
		.availability = AVAILABILITY_TOML,
	}, {
		.id = 3001,
		.name = "arguments",
		.type = &gt_string_array,
		.offset = offsetof(struct rpki_config, rsync.args),
		.doc = "Arguments to send to the RSYNC program call",
		.availability = AVAILABILITY_TOML,
	},
	{ 0 },
};

static const struct option_field output_fields[] = {
	{
		.id = 'c',
		.name = "color-output",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, output.color),
		.doc = "Print ANSI color codes.",
	}, {
		.id = 4000,
		.name = "output-file-name-format",
		.type = &gt_filename_format,
		.offset = offsetof(struct rpki_config, output.filename_format),
		.doc = "File name variant to print during debug/error messages",
	}, {
		.id = 'o',
		.name = "roa-output-file",
		.type = &gt_out_file,
		.offset = offsetof(struct rpki_config, output.roa_output),
		.doc = "File where the valid ROAs will be dumped.",
	},
	{ 0 },
};

static const struct group_fields groups[] = {
	{
		.name = "root",
		.options = global_fields,
	}, {
		.name = "tal",
		.options = tal_fields,
	}, {
		.name = "rsync",
		.options = rsync_fields,
	}, {
		.name = "output",
		.options = output_fields,
	},
	{ NULL },
};

/**
 * Returns true if @field is the descriptor of one of the members of the
 * struct rpki_config structure, false otherwise.
 * (Alternatively: Returns true if @field->offset is valid, false otherwise.)
 */
static bool
is_rpki_config_field(struct option_field const *field)
{
	return field->handler == NULL;
}

void *
get_rpki_config_field(struct option_field const *field)
{
	return ((unsigned char *) &rpki_config) + field->offset;
}

static void
print_bool(struct group_fields const *group, struct option_field const *field,
    void *_value)
{
	bool *value = _value;
	pr_info("%s.%s: %s", group->name, field->name,
	    (*value) ? "true" : "false");
}

static void
print_u_int(struct group_fields const *group, struct option_field const *field,
    void *value)
{
	pr_info("%s.%s: %u", group->name, field->name,
	    *((unsigned int *) value));
}

static void
print_string(struct group_fields const *group, struct option_field const *field,
    void *value)
{
	pr_info("%s.%s: %s", group->name, field->name, *((char **) value));
}

static void
print_string_array(struct group_fields const *group,
    struct option_field const *field, void *_value)
{
	struct string_array *value = _value;
	size_t i;

	pr_info("%s.%s:", group->name, field->name);
	pr_indent_add();

	if (value->length == 0)
		pr_info("<Nothing>");
	else for (i = 0; i < value->length; i++)
		pr_info("%s", value->array[i]);

	pr_indent_rm();
}

static void
print_sync_strategy(struct group_fields const *group,
    struct option_field const *field, void *value)
{
	enum sync_strategy *strategy = value;
	char const *str = "<unknown>";

	switch (*strategy) {
	case SYNC_OFF:
		str = SYNC_VALUE_OFF;
		break;
	case SYNC_STRICT:
		str = SYNC_VALUE_STRICT;
		break;
	case SYNC_ROOT:
		str = SYNC_VALUE_ROOT;
		break;
	}

	pr_info("%s.%s: %s", group->name, field->name, str);
}

static void
print_filename_format(struct group_fields const *group,
    struct option_field const *field, void *value)
{
	enum filename_format *format = value;
	char const *str = "<unknown>";

	switch (*format) {
	case FNF_GLOBAL:
		str = FNF_VALUE_GLOBAL;
		break;
	case FNF_LOCAL:
		str = FNF_VALUE_LOCAL;
		break;
	case FNF_NAME:
		str = FNF_VALUE_NAME;
		break;
	}

	pr_info("%s.%s: %s", group->name, field->name, str);
}

static void
print_out_file(struct group_fields const *group,
    struct option_field const *field, void *value)
{
	struct config_out_file *file = value;
	pr_info("%s.%s: %s", group->name, field->name, file->file_name);
}

static int
parse_argv_bool(struct option_field const *field, char const *str, void *result)
{
	bool *value = result;

	if (str == NULL) {
		*value = true;
		return 0;
	}

	if (strcmp(str, "true") == 0) {
		*value = true;
		return 0;
	}

	if (strcmp(str, "false") == 0) {
		*value = false;
		return 0;
	}

	return pr_err("Cannot parse '%s' as a bool (true|false).", str);
}

static int
parse_argv_u_int(struct option_field const *field, char const *str, void *_result)
{
	unsigned long parsed;
	int *result;

	if (field->type->has_arg != required_argument || str == NULL) {
		return pr_err("Integer options ('%s' in this case) require an argument.",
		    field->name);
	}

	errno = 0;
	parsed = strtoul(str, NULL, 10);
	if (errno)
		return pr_errno(errno, "'%s' is not an unsigned integer", str);

	if (parsed < field->min || field->max < parsed) {
		return pr_err("'%lu' is out of bounds (%u-%u).", parsed,
		    field->min, field->max);
	}

	result = _result;
	*result = parsed;
	return 0;
}

static int
parse_argv_string(struct option_field const *field, char const *str, void *_result)
{
	char **result = _result;

	/* Remove the previous value (usually the default). */
	field->type->free(result);

	if (field->type->has_arg != required_argument || str == NULL) {
		return pr_err("String options ('%s' in this case) require an argument.",
		    field->name);
	}

	/* tomlc99 frees @str early, so work with a copy. */
	*result = strdup(str);
	return ((*result) != NULL) ? 0 : pr_enomem();
}

static int
parse_argv_sync_strategy(struct option_field const *field, char const *str,
    void *_result)
{
	enum sync_strategy *result = _result;

	if (strcmp(str, SYNC_VALUE_OFF) == 0)
		*result = SYNC_OFF;
	else if (strcmp(str, SYNC_VALUE_STRICT) == 0)
		*result = SYNC_STRICT;
	else if (strcmp(str, SYNC_VALUE_ROOT) == 0)
		*result = SYNC_ROOT;
	else
		return pr_err("Unknown synchronization strategy: '%s'", str);

	return 0;
}

static int
parse_argv_filename_format(struct option_field const *field, char const *str,
    void *_result)
{
	enum filename_format *result = _result;

	if (strcmp(str, FNF_VALUE_GLOBAL) == 0)
		*result = FNF_GLOBAL;
	else if (strcmp(str, FNF_VALUE_LOCAL) == 0)
		*result = FNF_LOCAL;
	else if (strcmp(str, FNF_VALUE_NAME) == 0)
		*result = FNF_NAME;
	else
		return pr_err("Unknown file name format: '%s'", str);

	return 0;
}

static int
parse_argv_out_file(struct option_field const *field, char const *file_name,
    void *_result)
{
	struct config_out_file *file = _result;

	field->type->free(file);

	file->file_name = strdup(file_name);
	if (file->file_name == NULL)
		return pr_enomem();

	file->fd = fopen(file_name, "w");
	if (file->fd == NULL) {
		free(file->file_name);
		file->file_name = NULL;
		return pr_errno(errno, "Could not open file '%s'", file_name);
	}

	return 0;
}

static int
parse_toml_bool(struct option_field const *opt, struct toml_table_t *toml,
    void *_result)
{
	const char *raw;
	int value;
	bool *result;

	raw = toml_raw_in(toml, opt->name);
	if (raw == NULL)
		return pr_err("TOML boolean '%s' was not found.", opt->name);
	if (toml_rtob(raw, &value) == -1)
		return pr_err("Cannot parse '%s' as a boolean.", raw);

	result = _result;
	*result = value;
	return 0;
}

static int
parse_toml_u_int(struct option_field const *opt, struct toml_table_t *toml,
    void *_result)
{
	const char *raw;
	int64_t value;
	unsigned int *result;

	raw = toml_raw_in(toml, opt->name);
	if (raw == NULL)
		return pr_err("TOML integer '%s' was not found.", opt->name);
	if (toml_rtoi(raw, &value) == -1)
		return pr_err("Cannot parse '%s' as an integer.", raw);

	if (value < opt->min || opt->max < value) {
		return pr_err("Integer '%s' is out of range (%u-%u).",
		    opt->name, opt->min, opt->max);
	}

	result = _result;
	*result = value;
	return 0;
}

static int
parse_toml_string(struct option_field const *opt, struct toml_table_t *toml,
    void *_result)
{
	const char *raw;
	char *value;
	char **result;

	/* Remove the previous value (usually the default). */
	opt->type->free(_result);

	raw = toml_raw_in(toml, opt->name);
	if (raw == NULL)
		return pr_err("TOML string '%s' was not found.", opt->name);
	if (toml_rtos(raw, &value) == -1)
		return pr_err("Cannot parse '%s' as a string.", raw);

	result = _result;
	*result = value;
	return 0;
}

static int
parse_toml_sync_strategy(struct option_field const *opt,
    struct toml_table_t *toml, void *_result)
{
	int error;
	char *string;

	string = NULL;
	error = parse_toml_string(opt, toml, &string);
	if (error)
		return error;

	error = parse_argv_sync_strategy(opt, string, _result);

	free(string);
	return error;
}

static int
parse_toml_string_array(struct option_field const *opt,
    struct toml_table_t *toml, void *_result)
{
	toml_array_t *array;
	int array_len;
	int i;
	const char *raw;
	struct string_array *result = _result;
	int error;

	/* Remove the previous value (usually the default). */
	opt->type->free(_result);

	array = toml_array_in(toml, opt->name);
	if (array == NULL)
		return pr_err("TOML array '%s' was not found.", opt->name);
	array_len = toml_array_nelem(array);

	result->array = malloc(array_len * sizeof(char *));
	if (result->array == NULL)
		return pr_enomem();
	result->length = array_len;

	for (i = 0; i < array_len; i++) {
		raw = toml_raw_at(array, i);
		if (raw == NULL) {
			error = pr_crit("Array index %d is NULL.", i);
			goto fail;
		}
		if (toml_rtos(raw, &result->array[i]) == -1) {
			error = pr_err("Cannot parse '%s' as a string.", raw);
			goto fail;
		}
	}

	return 0;

fail:
	free(result->array);
	result->length = 0;
	return error;
}

static int
parse_toml_filename_format(struct option_field const *opt,
    struct toml_table_t *toml, void *_result)
{
	int error;
	char *string;

	string = NULL;
	error = parse_toml_string(opt, toml, &string);
	if (error)
		return error;

	error = parse_argv_filename_format(opt, string, _result);

	free(string);
	return error;
}

static int
parse_toml_out_file(struct option_field const *opt, struct toml_table_t *toml,
    void *_result)
{
	char *file_name;
	int error;

	file_name = NULL;
	error = parse_toml_string(opt, toml, &file_name);
	if (error)
		return error;

	error = parse_argv_out_file(opt, file_name, _result);

	free(file_name);
	return error;
}

static int
handle_help(struct option_field const *field, char *arg)
{
	print_usage(stdout, true);
	exit(0);
}

static int
handle_usage(struct option_field const *field, char *arg)
{
	print_usage(stdout, false);
	exit(0);
}

static int
handle_version(struct option_field const *field, char *arg)
{
	printf("0.0.1\n");
	exit(0);
}

static int
handle_toml(struct option_field const *field, char *file_name)
{
	return set_config_from_file(file_name);
}

static void
free_string(void *_string)
{
	char **string = _string;
	free(*string);
	*string = NULL;
}

static void
free_string_array(void *_array)
{
	struct string_array *array = _array;
	size_t i;

	for (i = 0; i < array->length; i++)
		free(array->array[i]);
	free(array->array);

	array->array = NULL;
	array->length = 0;
}

static void
free_out_file(void *_file)
{
	struct config_out_file *file = _file;

	if (file->fd != NULL) {
		fclose(file->fd);
		file->fd = NULL;
	}

	free(file->file_name);
	file->file_name = NULL;
}

static bool
is_alphanumeric(int chara)
{
	return ('a' <= chara && chara <= 'z')
	    || ('A' <= chara && chara <= 'Z')
	    || ('0' <= chara && chara <= '9');
}

/**
 * "struct option" is the array that getopt expects.
 * "struct args_flag" is our option metadata.
 */
static int
construct_getopt_options(struct option **_long_opts, char **_short_opts)
{
	struct group_fields const *group;
	struct option_field const *opt;
	struct option *long_opts;
	char *short_opts;
	unsigned int total_long_options;
	unsigned int total_short_options;

	total_long_options = 0;
	total_short_options = 0;
	FOREACH_OPTION(groups, group, opt, AVAILABILITY_GETOPT) {
		total_long_options++;
		if (is_alphanumeric(opt->id)) {
			total_short_options++;
			if (opt->type->has_arg != no_argument)
				total_short_options++; /* ":" */
		}
	}

	/* +1 NULL end, means end of array. */
	long_opts = calloc(total_long_options + 1, sizeof(struct option));
	if (long_opts == NULL)
		return pr_enomem();
	short_opts = malloc(total_short_options + 1);
	if (short_opts == NULL) {
		free(long_opts);
		return pr_enomem();
	}

	*_long_opts = long_opts;
	*_short_opts = short_opts;

	FOREACH_OPTION(groups, group, opt, AVAILABILITY_GETOPT) {
		long_opts->name = opt->name;
		long_opts->has_arg = opt->type->has_arg;
		long_opts->flag = NULL;
		long_opts->val = opt->id;
		long_opts++;

		if (is_alphanumeric(opt->id)) {
			*short_opts = opt->id;
			short_opts++;
			if (opt->type->has_arg != no_argument) {
				*short_opts = ':';
				short_opts++;
			}
		}
	}

	*short_opts = '\0';
	return 0;
}

static void
print_config(void)
{
	struct group_fields const *grp;
	struct option_field const *opt;

	pr_info("Configuration {");
	pr_indent_add();

	FOREACH_OPTION(groups, grp, opt, 0xFFFF)
		if (is_rpki_config_field(opt) && opt->type->print != NULL)
			opt->type->print(grp, opt, get_rpki_config_field(opt));

	pr_indent_rm();
	pr_info("}");
}

static int
set_default_values(void)
{
	static char const *default_rsync_args[] = {
		"--recursive",
		"--delete",
		"--times",
		"--contimeout=20",
		"$REMOTE",
		"$LOCAL",
	};

	size_t i;

	/*
	 * Values that might need to be freed WILL be freed, so use heap
	 * duplicates.
	 */

	rpki_config.tal = NULL;

	rpki_config.local_repository = strdup("repository/");
	if (rpki_config.local_repository == NULL)
		return pr_enomem();

	rpki_config.sync_strategy = SYNC_STRICT;
	rpki_config.shuffle_uris = false;
	rpki_config.maximum_certificate_depth = 32;

	rpki_config.rsync.program = strdup("rsync");
	if (rpki_config.rsync.program == NULL)
		goto revert_repository;

	rpki_config.rsync.args.length = ARRAY_LEN(default_rsync_args);
	rpki_config.rsync.args.array = calloc(rpki_config.rsync.args.length,
	    sizeof(char *));
	if (rpki_config.rsync.args.array == NULL)
		goto revert_rsync_program;

	for (i = 0; i < ARRAY_LEN(default_rsync_args); i++) {
		rpki_config.rsync.args.array[i] = strdup(default_rsync_args[i]);
		if (rpki_config.rsync.args.array[i] == NULL)
			goto revert_rsync_args;
	}

	rpki_config.output.color = false;
	rpki_config.output.filename_format = FNF_GLOBAL;
	rpki_config.output.roa_output.fd = NULL;
	rpki_config.output.roa_output.file_name = NULL;

	return 0;

revert_rsync_args:
	for (i = 0; i < ARRAY_LEN(default_rsync_args); i++)
		free(rpki_config.rsync.args.array[i]);
	free(rpki_config.rsync.args.array);
revert_rsync_program:
	free(rpki_config.rsync.program);
revert_repository:
	free(rpki_config.local_repository);
	return pr_enomem();
}

static int
validate_config(void)
{
	return (rpki_config.tal != NULL)
	    ? 0
	    : pr_err("The TAL file (--tal) is mandatory.");
}

static void
print_usage(FILE *stream, bool print_doc)
{
	struct group_fields const *group;
	struct option_field const *option;
	char const *arg_doc;

	fprintf(stream, "Usage: %s\n", program_name);
	FOREACH_OPTION(groups, group, option, AVAILABILITY_GETOPT) {
		fprintf(stream, "\t[");
		fprintf(stream, "--%s", option->name);

		if (option->arg_doc != NULL)
			arg_doc = option->arg_doc;
		else if (option->type->arg_doc != NULL)
			arg_doc = option->type->arg_doc;
		else
			arg_doc = NULL;

		switch (option->type->has_arg) {
		case no_argument:
			break;
		case optional_argument:
		case required_argument:
			if (arg_doc != NULL)
				fprintf(stream, "=%s", arg_doc);
			break;
		}

		fprintf(stream, "]\n");

		if (print_doc)
			fprintf(stream, "\t    (%s)\n", option->doc);
	}
}


static int
handle_opt(int opt)
{
	struct group_fields const *group;
	struct option_field const *option;

	FOREACH_OPTION(groups, group, option, AVAILABILITY_GETOPT) {
		if (option->id == opt) {
			return is_rpki_config_field(option)
			    ? option->type->parse.argv(option, optarg,
			          get_rpki_config_field(option))
			    : option->handler(option, optarg);
		}
	}

	pr_err("Unrecognized option: %d", opt);
	return -ESRCH;
}

int
handle_flags_config(int argc, char **argv)
{
	struct option *long_opts;
	char *short_opts;
	int opt;
	int error;

	program_name = argv[0];
	error = set_default_values();
	if (error)
		return error;

	long_opts = NULL;
	short_opts = NULL;
	error = construct_getopt_options(&long_opts, &short_opts);
	if (error)
		goto end; /* Error msg already printed. */

	while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL))
	    != -1) {
		error = handle_opt(opt);
		if (error)
			goto end;
	}

	/*
	 * This triggers when the user runs something like
	 * `rpki-validator disable-rsync` instead of
	 * `rpki-validator --disable-rsync`.
	 * This program does not have unflagged payload.
	 */
	if (optind < argc) {
		error = pr_err("I don't know what '%s' is.", argv[optind]);
		goto end;
	}

	error = validate_config();

end:
	if (error)
		free_rpki_config();
	else
		print_config();

	free(long_opts);
	free(short_opts);
	return error;

}

void
get_group_fields(struct group_fields const **group_fields)
{
	*group_fields = groups;
}

char const *
config_get_tal(void)
{
	return rpki_config.tal;
}

char const *
config_get_local_repository(void)
{
	return rpki_config.local_repository;
}

enum sync_strategy
config_get_sync_strategy(void)
{
	return rpki_config.sync_strategy;
}

bool
config_get_shuffle_uris(void)
{
	return rpki_config.shuffle_uris;
}

unsigned int
config_get_max_cert_depth(void)
{
	return rpki_config.maximum_certificate_depth;
}

bool
config_get_color_output(void)
{
	return rpki_config.output.color;
}

enum filename_format
config_get_filename_format(void)
{
	return rpki_config.output.filename_format;
}

FILE *
config_get_roa_output(void)
{
	return (rpki_config.output.roa_output.fd != NULL)
	    ? rpki_config.output.roa_output.fd
	    : stdout;
}

char *
config_get_rsync_program(void)
{
	return rpki_config.rsync.program;
}

struct string_array const *
config_get_rsync_args(void)
{
	return &rpki_config.rsync.args;
}

void
free_rpki_config(void)
{
	struct group_fields const *group;
	struct option_field const *option;

	FOREACH_OPTION(groups, group, option, 0xFFFF)
		if (is_rpki_config_field(option) && option->type->free != NULL)
			option->type->free(get_rpki_config_field(option));
}
