#include "config.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "common.h"
#include "log.h"
#include "toml_handler.h"
#include "config/boolean.h"
#include "config/out_file.h"
#include "config/str.h"
#include "config/uint.h"

/**
 * Please note that this is actually two `for`s stacked together, so don't use
 * `break` nor `continue` to get out.
 */
#define FOREACH_OPTION(groups, grp, opt, type)			\
	for (grp = groups; grp->name != NULL; grp++)		\
		for (opt = grp->options; opt->id != 0; opt++)	\
			if ((opt->availability == 0) ||		\
			    (opt->availability & type))

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

#define DECLARE_HANDLE_FN(name)						\
	static int name(						\
	    struct option_field const *,				\
	    char *							\
	)
DECLARE_HANDLE_FN(handle_help);
DECLARE_HANDLE_FN(handle_usage);
DECLARE_HANDLE_FN(handle_version);
DECLARE_HANDLE_FN(handle_toml);

static char const *program_name;
static struct rpki_config rpki_config;

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
