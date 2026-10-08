#include "common/config.h"

#include <errno.h>
#include <getopt.h>
#include <unistd.h>

#include "common/alloc.h"
#include "common/log.h"
#include "configure_ac.h"

/*
 * An ARGP option that takes no arguments, is not correlated to any rpki_config
 * fields, and is entirely managed by its handler function.
 */
const struct global_type gt_callback = {
	.has_arg = no_argument,
};

static bool
is_alphanumeric(int chara)
{
	return ('a' <= chara && chara <= 'z')
	    || ('A' <= chara && chara <= 'Z')
	    || ('0' <= chara && chara <= '9');
}

/*
 * "struct option" is the array that getopt expects.
 * "struct option_field" is our option metadata.
 */
static void
build_opts(struct option **_long_opts, char **_short_opts)
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
	long_opts = pcalloc(total_long_options + 1, sizeof(struct option));
	short_opts = pmalloc(total_short_options + 1);

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
}

/*
 * Returns true if @field is the descriptor of one of the members of the
 * struct rpki_config structure, false otherwise.
 */
static bool
is_rpki_config_field(struct option_field const *field)
{
	return field->handler == NULL;
}

void *
get_rpki_config_field(struct option_field const *field, void *cfg)
{
	return ((unsigned char *)cfg) + field->offset;
}

static int
handle_opt(int opt, void *cfg)
{
	struct option_field const *option;

	FOREACH_OPTION(options, option, AVAILABILITY_GETOPT) {
		if (option->id == opt) {
			if (option->deprecated)
				pr_wrn("'%s' is deprecated.", option->name);

			return is_rpki_config_field(option)
			    ? option->type->parse.argv(option, optarg,
			          get_rpki_config_field(option, cfg))
			    : option->handler(option, optarg);
		}
	}

	pr_err("Unrecognized option: %d", opt);
	return ESRCH;
}

int
parse_args(int argc, char **argv, void *cfg)
{
	struct option *lopts; /* long opts */
	char *sopts; /* short opts */
	int opt;
	int error = 0;

	build_opts(&lopts, &sopts);

	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) != -1) {
		error = handle_opt(opt, cfg);
		if (error)
			break;
	}

	free(lopts);
	free(sopts);
	return error;
}

void
free_rpki_config(void *cfg)
{
	struct option_field const *option;

	FOREACH_OPTION(options, option, 0xFFFF)
		if (is_rpki_config_field(option) && option->type->free != NULL)
			option->type->free(get_rpki_config_field(option, cfg));
}

static void
print_usage(FILE *stream, bool print_doc)
{
	struct option_field const *option;
	char const *arg_doc;

	fprintf(stream, "Usage:\n");
	FOREACH_OPTION(options, option, AVAILABILITY_GETOPT) {
		if (option->deprecated)
			continue;

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

int
handle_help(struct option_field const *field, char *arg)
{
	print_usage(stdout, true);
	exit(0);
}

int
handle_usage(struct option_field const *field, char *arg)
{
	print_usage(stdout, false);
	exit(0);
}

int
handle_version(struct option_field const *field, char *arg)
{
	printf(PACKAGE_STRING "\n");
	exit(0);
}
