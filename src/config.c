#include "config.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "log.h"
#include "toml_handler.h"

#define FOREACH_OPTION(groups, grp, opt, type)			\
	for (grp = groups; grp->name != NULL; grp++)		\
		for (opt = grp->options; opt->id != 0; opt++)	\
			if ((opt->availability == 0) ||		\
			    (opt->availability & type))

struct rpki_config {
	/** TAL file name/location. */
	char const *tal;
	/** Path of our local clone of the repository */
	char const *local_repository;
	/** Disable rsync downloads? */
	bool disable_rsync;
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
	/** Print ANSI color codes? */
	bool color_output;
};


static void print_usage(FILE *stream);

void print_bool(struct group_fields const *, struct option_field const *,
    void *);
void print_u_int(struct group_fields const *, struct option_field const *,
    void *);
void print_string(struct group_fields const *, struct option_field const *,
    void *);
static int parse_bool(struct option_field const *, char const *, void *);
static int parse_u_int(struct option_field const *, char const *, void *);
static int parse_string(struct option_field const *, char const *, void *);
static int handle_help(struct option_field const *, char *);
static int handle_usage(struct option_field const *, char *);
static int handle_version(struct option_field const *, char *);
static int handle_toml(struct option_field const *, char *);
static void free_string(void *);

static char const *program_name;
static struct rpki_config rpki_config;

static const struct global_type gt_bool = {
	.has_arg = no_argument,
	.size = sizeof(bool),
	.print = print_bool,
	.parse = parse_bool,
	.arg_doc = "true|false",
};

static const struct global_type gt_u_int = {
	.has_arg = required_argument,
	.size = sizeof(unsigned int),
	.print = print_u_int,
	.parse = parse_u_int,
	.arg_doc = "<unsigned integer>",
};

static const struct global_type gt_string = {
	.has_arg = required_argument,
	.size = sizeof(char *),
	.print = print_string,
	.parse = parse_string,
	.free = free_string,
	.arg_doc = "<string>",
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
		.doc = "TOML file the configuration will be read from.",
		.arg_doc = "<file>",
		.availability = AVAILABILITY_GETOPT,
	}, {
		.id = 'r',
		.name = "local-repository",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, local_repository),
		.doc = "Local repository path.",
		.arg_doc = "<directory>",
	}, {
		.id = 1001,
		.name = "disable-rsync",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, disable_rsync),
		.doc = "Enable or disable rsync downloads.",
	}, {
		.id = 'c',
		.name = "color-output",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, color_output),
		.doc = "Print ANSI color codes?",
		.availability = AVAILABILITY_GETOPT,
	},
	{ 0 },
};

static const struct option_field tal_fields[] = {
	{
		.id = 't',
		.name = "tal",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, tal),
		.doc = "TAL file path",
		.arg_doc = "<file name>",
	}, {
		.id = 2000,
		.name = "shuffle-uris",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, shuffle_uris),
		.doc = "Shuffle URIs in the TAL.",
	}, {
		.id = 2001,
		.name = "maximum-certificate-depth",
		.type = &gt_u_int,
		.offset = offsetof(struct rpki_config,
		    maximum_certificate_depth),
		.doc = "Prevents arbitrarily long paths and loops.",
		.min = 1,
		/**
		 * It cannot be UINT_MAX, because then the actual number will
		 * overflow and will never be bigger than this.
		 */
		.max = UINT_MAX - 1,
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

static void *
get_rpki_config_field(struct option_field const *field)
{
	return ((unsigned char *) &rpki_config) + field->offset;
}

void
print_bool(struct group_fields const *group, struct option_field const *field,
    void *_value)
{
	bool *value = _value;
	pr_info("%s.%s: %s", group->name, field->name,
	    (*value) ? "true" : "false");
}

void
print_u_int(struct group_fields const *group, struct option_field const *field,
    void *value)
{
	pr_info("%s.%s: %u", group->name, field->name,
	    *((unsigned int *) value));
}

void
print_string(struct group_fields const *group, struct option_field const *field,
    void *value)
{
	pr_info("%s.%s: %s", group->name, field->name, *((char **) value));
}

static int
parse_bool(struct option_field const *field, char const *str, void *result)
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
parse_u_int(struct option_field const *field, char const *str, void *_result)
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
parse_string(struct option_field const *field, char const *str, void *_result)
{
	char **result = _result;

	if (field->type->has_arg != required_argument || str == NULL) {
		return pr_err("String options ('%s' in this case) require an argument.",
		    field->name);
	}

	/* tomlc99 frees @str early, so work with a copy. */
	*result = strdup(str);
	return ((*result) != NULL) ? 0 : pr_enomem();
}

static int
handle_help(struct option_field const *field, char *arg)
{
	print_usage(stdout);
	exit(0);
}

static int
handle_usage(struct option_field const *field, char *arg)
{
	print_usage(stdout);
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

int
parse_option(struct option_field const *field, char const *str)
{
	return field->type->parse(field, str,
	    get_rpki_config_field(field));
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
	rpki_config.tal = NULL;
	rpki_config.local_repository = strdup("repository/");
	if (rpki_config.local_repository == NULL)
		return pr_enomem();
	rpki_config.disable_rsync = false;
	rpki_config.shuffle_uris = false;
	rpki_config.maximum_certificate_depth = 32;
	return 0;
}

static int
validate_config(void)
{
	return (rpki_config.tal != NULL)
	    ? 0
	    : pr_err("The TAL file (--tal) is mandatory.");
}

static void
print_usage(FILE *stream)
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
			if(arg_doc == NULL)
				break;
			fprintf(stream, "=%s", arg_doc);
			break;
		}

		fprintf(stream, "]\n");
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
			    ? parse_option(option, optarg)
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

bool
config_get_enable_rsync(void)
{
	return !rpki_config.disable_rsync;
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
	return rpki_config.color_output;
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
