#include "config.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>

#include "common.h"
#include "json_handler.h"
#include "log.h"
#include "config/boolean.h"
#include "config/incidences.h"
#include "config/str.h"
#include "config/uint.h"
#include "config/uint32.h"

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
	/** TAL file name or directory. */
	char *tal;
	/** Path of our local clone of the repository */
	char *local_repository;
	/** Synchronization (currently only RSYNC) download strategy. */
	enum sync_strategy sync_strategy;
	/**
	 * Handle TAL URIs in random order?
	 * (https://tools.ietf.org/html/rfc7730#section-3, last
	 * paragraphs)
	 */
	bool shuffle_tal_uris;
	/**
	 * rfc6487#section-7.2, last paragraph.
	 * Prevents arbitrarily long paths and loops.
	 */
	unsigned int maximum_certificate_depth;
	/** File or directory where the .slurm file(s) is(are) located */
	char *slurm;

	struct {
		/** Enable/disable the RTR server. */
		bool enabled;
		/** The bound listening address of the RTR server. */
		char *address;
		/** The bound listening port of the RTR server. */
		char *port;
		/** Outstanding connections in the socket's listen queue */
		unsigned int backlog;

		/** Interval used to look for updates at VRPs location */
		unsigned int validation_interval;

		/*
		 * TODO (next iteration) Intervals used at End of data PDU
		 * uint32_t refresh_interval;
		 * uint32_t retry_interval;
		 * uint32_t expire_interval;
		 */
	} server;

	struct {
		char *program;
		struct {
			struct string_array flat;
			struct string_array recursive;
		} args;
	} rsync;

	struct {
		/** Print ANSI color codes? */
		bool color;
		/** Format in which file names will be printed. */
		enum filename_format filename_format;
	} log;

	struct {
		/** File where the validated ROAs will be stored */
		char *roa;
		/** TODO (next iteration) Add BGPsec output */
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
DECLARE_HANDLE_FN(handle_json);

static char const *program_name;
static struct rpki_config rpki_config;

/**
 * An ARGP option that takes no arguments, is not correlated to any rpki_config
 * fields, and is entirely managed by its handler function.
 */
static const struct global_type gt_callback = {
	.has_arg = no_argument,
};

static const struct option_field options[] = {

	/* ARGP-only, non-fields */
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
		.handler = handle_json,
		.doc = "JSON file additional configuration will be read from",
		.arg_doc = "<file>",
		.availability = AVAILABILITY_GETOPT,
	},

	/* Root fields */
	{
		.id = 't',
		.name = "tal",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, tal),
		.doc = "Path to the TAL file or TALs directory",
		.arg_doc = "<file or directory>",
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
		.id = 2000,
		.name = "shuffle-uris",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, shuffle_tal_uris),
		.doc = "Shuffle URIs in the TAL before accessing them",
	}, {
		.id = 1002,
		.name = "maximum-certificate-depth",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config,
		    maximum_certificate_depth),
		.doc = "Maximum allowable certificate chain length",
		.min = 1,
		/**
		 * It cannot be UINT_MAX, because then the actual number will
		 * overflow and will never be bigger than this.
		 */
		.max = UINT_MAX - 1,
	}, {
		.id = 1003,
		.name = "slurm",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, slurm),
		.doc = "Path to the SLURM file or SLURMs directory (files must have the extension .slurm)",
	},

	/* Server fields */
	{
		.id = 5000,
		.name = "server.enabled",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, server.enabled),
		.doc = "Enable or disable the RTR server.",
	}, {
		.id = 5001,
		.name = "server.address",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, server.address),
		.doc = "Address to which RTR server will bind itself to. Can be a name, in which case an address will be resolved.",
	}, {
		.id = 5002,
		.name = "server.port",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, server.port),
		.doc = "Port to which RTR server will bind itself to. Can be a string, in which case a number will be resolved.",
	}, {
		.id = 5003,
		.name = "server.backlog",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, server.backlog),
		.doc = "Maximum connections in the socket's listen queue",
		.min = 1,
		.max = SOMAXCONN,
	}, {
		.id = 5004,
		.name = "server.validation-interval",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config,
		    server.validation_interval),
		.doc = "Interval used to look for updates at VRPs location",
		/*
		 * RFC 6810 and 8210:
		 * "The cache MUST rate-limit Serial Notifies to no more
		 * frequently than one per minute."
		 * We do this by not getting new information more than once per
		 * minute.
		 */
		.min = 60,
		.max = UINT_MAX,
	},
	/*
	 * TODO (next iteration) RTRv1 intervals with values:
	 * - refresh: min = 1, max = 86400, default = 3600
	 * - retry: min = 1, max = 7200, default = 600
	 * - expire: min = 600, max = 172800, default = 7200
	 */

	/* RSYNC fields */
	{
		.id = 3000,
		.name = "rsync.program",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, rsync.program),
		.doc = "Name of the program needed to execute an RSYNC",
		.arg_doc = "<path to program>",
		.availability = AVAILABILITY_JSON,
	}, {
		.id = 3001,
		.name = "rsync.arguments-recursive",
		.type = &gt_string_array,
		.offset = offsetof(struct rpki_config, rsync.args.recursive),
		.doc = "RSYNC program arguments that will trigger a recursive RSYNC",
		.availability = AVAILABILITY_JSON,
	}, {
		.id = 3002,
		.name = "rsync.arguments-flat",
		.type = &gt_string_array,
		.offset = offsetof(struct rpki_config, rsync.args.flat),
		.doc = "RSYNC program arguments that will trigger a non-recursive RSYNC",
		.availability = AVAILABILITY_JSON,
	},

	/* Logging fields */
	{
		.id = 'c',
		.name = "log.color-output",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, log.color),
		.doc = "Print ANSI color codes",
	}, {
		.id = 4000,
		.name = "log.file-name-format",
		.type = &gt_filename_format,
		.offset = offsetof(struct rpki_config, log.filename_format),
		.doc = "File name variant to print during debug/error messages",
	},

	/* Incidences */
	{
		.id = 4001,
		.name = "incidences",
		.type = &gt_incidences,
		.doc = "Override actions on validation errors",
		.availability = AVAILABILITY_JSON,
	},

	/* Output files */
	{
		.id = 6000,
		.name = "output.roa",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, output.roa),
		.doc = "File where ROAs will be stored in CSV format, use '-' to print at console",
		.arg_doc = "<file>",
	},

	{ 0 },
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
handle_json(struct option_field const *field, char *file_name)
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
	struct option_field const *opt;
	struct option *long_opts;
	char *short_opts;
	unsigned int total_long_options;
	unsigned int total_short_options;

	total_long_options = 0;
	total_short_options = 0;
	FOREACH_OPTION(options, opt, AVAILABILITY_GETOPT) {
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

	FOREACH_OPTION(options, opt, AVAILABILITY_GETOPT) {
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
	struct option_field const *opt;

	pr_info("Configuration {");
	pr_indent_add();

	FOREACH_OPTION(options, opt, 0xFFFF)
		if (is_rpki_config_field(opt) && opt->type->print != NULL)
			opt->type->print(opt, get_rpki_config_field(opt));

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

	int error;

	/*
	 * Values that might need to be freed WILL be freed, so use heap
	 * duplicates.
	 */

	rpki_config.server.enabled = true;
	rpki_config.server.address = NULL;
	rpki_config.server.port = strdup("323");
	if (rpki_config.server.port == NULL)
		return pr_enomem();

	rpki_config.server.backlog = SOMAXCONN;
	rpki_config.server.validation_interval = 3600;

	rpki_config.tal = NULL;
	rpki_config.slurm = NULL;

	rpki_config.local_repository = strdup("/tmp/fort/repository");
	if (rpki_config.local_repository == NULL) {
		error = pr_enomem();
		goto revert_port;
	}

	rpki_config.sync_strategy = SYNC_ROOT;
	rpki_config.shuffle_tal_uris = false;
	rpki_config.maximum_certificate_depth = 32;

	rpki_config.rsync.program = strdup("rsync");
	if (rpki_config.rsync.program == NULL) {
		error = pr_enomem();
		goto revert_repository;
	}

	error = string_array_init(&rpki_config.rsync.args.recursive,
	    default_rsync_args, ARRAY_LEN(default_rsync_args));
	if (error)
		goto revert_rsync_program;
	/* Simply remove --recursive and --delete. */
	error = string_array_init(&rpki_config.rsync.args.flat,
	    default_rsync_args + 2, ARRAY_LEN(default_rsync_args) - 2);
	if (error)
		goto revert_recursive_array;

	rpki_config.log.color = false;
	rpki_config.log.filename_format = FNF_GLOBAL;

	rpki_config.output.roa = NULL;

	return 0;

revert_recursive_array:
	string_array_cleanup(&rpki_config.rsync.args.recursive);
revert_rsync_program:
	free(rpki_config.rsync.program);
revert_repository:
	free(rpki_config.local_repository);
revert_port:
	free(rpki_config.server.port);
	return error;
}

static int
validate_config(void)
{
	return (rpki_config.tal != NULL)
	    ? 0
	    : pr_err("The TAL file/directory (--tal) is mandatory.");
}

static void
print_usage(FILE *stream, bool print_doc)
{
	struct option_field const *option;
	char const *arg_doc;

	fprintf(stream, "Usage: %s\n", program_name);
	FOREACH_OPTION(options, option, AVAILABILITY_GETOPT) {
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
	struct option_field const *option;

	FOREACH_OPTION(options, option, AVAILABILITY_GETOPT) {
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

struct option_field const *
get_option_metadatas(void)
{
	return options;
}

bool
config_get_server_enabled(void)
{
	return rpki_config.server.enabled;
}

char const *
config_get_server_address(void)
{
	return rpki_config.server.address;
}

char const *
config_get_server_port(void)
{
	return rpki_config.server.port;
}

int
config_get_server_queue(void)
{
	/*
	 * The range of this is 1-<small number>, so adding signedness is safe.
	 */
	return rpki_config.server.backlog;
}

unsigned int
config_get_validation_interval(void)
{
	return rpki_config.server.validation_interval;
}

char const *
config_get_slurm(void)
{
	return rpki_config.slurm;
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
config_get_shuffle_tal_uris(void)
{
	return rpki_config.shuffle_tal_uris;
}

unsigned int
config_get_max_cert_depth(void)
{
	return rpki_config.maximum_certificate_depth;
}

bool
config_get_color_output(void)
{
	return rpki_config.log.color;
}

enum filename_format
config_get_filename_format(void)
{
	return rpki_config.log.filename_format;
}

char *
config_get_rsync_program(void)
{
	return rpki_config.rsync.program;
}

struct string_array const *
config_get_rsync_args(bool is_ta)
{
	switch (rpki_config.sync_strategy) {
	case SYNC_ROOT:
		return &rpki_config.rsync.args.recursive;
	case SYNC_ROOT_EXCEPT_TA:
		return is_ta
		    ? &rpki_config.rsync.args.flat
		    : &rpki_config.rsync.args.recursive;
	case SYNC_STRICT:
		return &rpki_config.rsync.args.flat;
	case SYNC_OFF:
		break;
	}

	pr_crit("Invalid sync strategy: '%u'", rpki_config.sync_strategy);
}

char const *
config_get_output_roa(void)
{
	return rpki_config.output.roa;
}

void
free_rpki_config(void)
{
	struct option_field const *option;

	FOREACH_OPTION(options, option, 0xFFFF)
		if (is_rpki_config_field(option) && option->type->free != NULL)
			option->type->free(get_rpki_config_field(option));
}
