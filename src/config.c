#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "common.h"
#include "log.h"
#include "toml_handler.h"

#define OPT_FIELD_ARRAY_LEN(array) ARRAY_LEN(array) - 1

struct rpki_config {
	/* tal file path*/
	char *tal;
	/* Local repository path */
	char *local_repository;
	/* Enable rsync downloads */
	bool enable_rsync;
	/* Shuffle uris in tal */
	bool shuffle_uris;
	/*
	 * rfc6487#section-7.2, last paragraph.
	 * Prevents arbitrarily long paths and loops.
	 */
	unsigned int maximum_certificate_depth;
};

static int parse_bool(struct option_field *, char *, void *);
static int parse_u_int(struct option_field *, char *, void *);
static void _free_rpki_config(struct rpki_config *);

static struct rpki_config rpki_config;

static struct global_type gt_bool = {
	.id = GTI_BOOL,
	.name = "Boolean",
	.size = sizeof(bool),
	.parse = parse_bool,
	.candidates = "true|false",
};

static struct global_type gt_string = {
	.id = GTI_STRING,
	.name = "String",
};

static struct global_type gt_u_int = {
	.id = GTI_U_INT,
	.name = "Unsigned Int",
	.size = sizeof(unsigned int),
	.parse = parse_u_int,
	.candidates = "NUM",
};

static struct option manual_long_opts[] = {
	{
		.name = "configuration-file",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'f',
	},
};


static struct option_field global_fields[] = {
	{
		.name = "local-repository",
		.type = &gt_string,
		.doc = "Local repository path.",
		.offset = offsetof(struct rpki_config, local_repository),
		.has_arg = required_argument,
		.short_opt = 0,
		.required = true,
		.candidates = "path",
	}, {
		.name = "enable-rsync",
		.type = &gt_bool,
		.doc = "Enable or disable rsync downloads.",
		.offset = offsetof(struct rpki_config, enable_rsync),
		.has_arg = optional_argument,
		.short_opt = 0,
		.required = false,
	},
	{ NULL },
};

static struct option_field tal_fields[] = {
	{
		.name = "tal",
		.type = &gt_string,
		.doc = "TAL file path",
		.offset = offsetof(struct rpki_config, tal),
		.has_arg = required_argument,
		.short_opt = 0,
		.required = true,
		.candidates = "file",
	}, {
		.name = "shuffle-uris",
		.type = &gt_bool,
		.doc = "Shuffle URIs in the TAL.",
		.offset = offsetof(struct rpki_config, shuffle_uris),
		.has_arg = optional_argument,
		.short_opt = 0,
		.required = false,
	}, {
		.name = "maximum-certificate-depth",
		.type = &gt_u_int,
		.doc = "Prevents arbitrarily long paths and loops.",
		.offset = offsetof(struct rpki_config,
		    maximum_certificate_depth),
		.has_arg = required_argument,
		.short_opt = 0,
		.min = 1,
		/**
		 * It cannot be UINT_MAX, because then the actual number will
		 * overflow and will never be bigger than this.
		 */
		.max = 	UINT_MAX - 1,
		.required = false,
	},
	{ NULL },
};



static struct group_fields fields[] = {
	{
		.group_name = "root",
		.options = global_fields,
		.options_len = OPT_FIELD_ARRAY_LEN(global_fields),
	},
	{
		.group_name = "tal",
		.options = tal_fields,
		.options_len = OPT_FIELD_ARRAY_LEN(tal_fields),
	},
	{ NULL },
};

static int
str_to_bool(const char *str, bool *bool_out)
{
	if (strcasecmp(str, "true") == 0 || strcasecmp(str, "1") == 0 ||
	    strcasecmp(str, "yes") == 0 || strcasecmp(str, "on") == 0) {
		*bool_out = true;
		return 0;
	}

	if (strcasecmp(str, "false") == 0 || strcasecmp(str, "0") == 0 ||
	    strcasecmp(str, "no") == 0 || strcasecmp(str, "off") == 0) {
		*bool_out = false;
		return 0;
	}

	return pr_err("Cannot parse '%s' as a bool "
			"(true|false|1|0|yes|no|on|off).", str);
}

static int
parse_bool(struct option_field *field, char *str, void *result)
{
	bool *value = result;

	switch (field->has_arg) {
	case no_argument:
		*value = true;
		return 0;
		break;
	case optional_argument:
		if (str == NULL) {
			*value = true;
			break;
		}
		/* FALLTHROUGH */
	case required_argument:
		return str_to_bool(str, result);
	}

	return 0;
}

static int str_to_ull(const char *str, char **endptr,
    const unsigned long long int min,
    const unsigned long long int max,
    unsigned long long int *result)
{
	unsigned long long int parsed;

	errno = 0;
	parsed = strtoull(str, endptr, 10);
	if (errno)
		return pr_errno(errno, "'%s' is not an unsigned integer", str);

	if (parsed < min || max < parsed)
		return pr_err("'%s' is out of bounds (%llu-%llu).", str, min,
		    max);

	*result = parsed;
	return 0;
}

static int
str_to_unsigned_int(const char *str, unsigned int *out, unsigned int min,
    unsigned int max)
{
	unsigned long long int result = 0;
	int error;

	error = str_to_ull(str, NULL, min, max, &result);

	*out = result;
	return error;
}

static int
parse_u_int(struct option_field *field, char *str, void *result)
{
	unsigned int *value = result;

	if (str == NULL)
		return pr_err("String cannot be NULL");

	return str_to_unsigned_int(str, value, field->min, field->max);
}

static int
construct_options(struct args_flag **flags, struct option **long_options,
    int *flags_len)
{
	struct option_field *tmp;
	struct group_fields *tmp_all_fields;
	struct args_flag *result_flags;
	struct option *result_options;
	unsigned int total_len, i, result_idx,
	    extra_long_options;

	tmp_all_fields = fields;
	total_len = 0;
	while (tmp_all_fields->group_name != NULL) {
		total_len += tmp_all_fields->options_len;
		tmp_all_fields += 1;
	}

	/* +1 NULL end, means end of array. */
	result_flags = calloc(total_len + 1, sizeof(struct args_flag));
	if (result_flags == NULL)
		return pr_enomem();

	extra_long_options = ARRAY_LEN(manual_long_opts);

	result_options = calloc(total_len
	    + extra_long_options /* extra options handled manually. */
	    + 1, /* long options must end with zeros */
	    sizeof(struct option));
	if (result_options == NULL) {
		free(result_flags);
		return pr_enomem();
	}

	result_idx = 0;
	tmp_all_fields = fields;
	while (tmp_all_fields->group_name != NULL) {
		tmp = tmp_all_fields->options;
		while(tmp->name != NULL) {
			result_flags[result_idx].field = tmp;

			result_options[result_idx].name = tmp->name;
			result_options[result_idx].has_arg = tmp->has_arg;
			result_options[result_idx].val = tmp->short_opt;
			result_options[result_idx].flag = NULL;

			result_idx++;
			tmp += 1;
		}
		tmp_all_fields += 1;
	}

	for (i = 0; i < extra_long_options; i++) {
		result_options[result_idx].name = manual_long_opts[i].name;
		result_options[result_idx].has_arg = manual_long_opts[i].has_arg;
		result_options[result_idx].val = manual_long_opts[i].val;
		result_options[result_idx].flag = manual_long_opts[i].flag;

		result_idx++;
	}

	*flags = result_flags;
	*flags_len = total_len;
	*long_options = result_options;

	return 0;
}

static int
set_string(void **field, char *str)
{
	char *result;

	/* malloc the string, because if the string comes from TOML_HANDLER,
	 * the string is freed later in that function. */
	result = malloc(strlen(str) + 1);
	if (result == NULL)
		return pr_enomem();

	strcpy(result, str);
	*field = result;

	return 0;
}

static void
set_config_param_for_string(void **field, void **config_param)
{
	*config_param = *field;
}

int
handle_option(struct rpki_config *config, struct option_field *field, char *str)
{
	void *config_param;
	int error = 0;

	/**
	 * TODO Should we use a switch case?
	 * In order to avoid:
	 * warning: pointer of type ‘void *’ used in arithmetic
	 * [-Wpointer-arith]
	 * https://stackoverflow.com/questions/23357442/
	 * dynamically-access-member-variable-of-a-structure
	 */
	config_param = config;
	config_param += field->offset;

	if (field->type == &gt_string) {
		error = set_string(config_param, str);
		if (error)
			return error;
		set_config_param_for_string(config_param, &config_param);
	} else if (field->type->parse != NULL){
		error = field->type->parse(field, str, config_param);
	}

	if (error)
		return error;

	if (field->validate != NULL)
		error = field->validate(field, config_param);
	else if (field->type->validate != NULL)
		error = field->type->validate(field, config_param);

	return error;
}

int
check_missing_flags(struct args_flag *flag)
{
	char *candidate = NULL;

	if (flag->is_set)
		return 0;
	if (!flag->field->required)
		return 0;

	printf("Missing param: %s", flag->field->name);
	switch (flag->field->has_arg) {
	case no_argument:
		break;
	case optional_argument:
		if (flag->field->candidates != NULL)
			candidate = flag->field->candidates;
		else if (flag->field->type->candidates != NULL)
			candidate = flag->field->type->candidates;
		if (candidate != NULL)
			printf("[=%s]", candidate);
		break;
	case required_argument:
		if (flag->field->candidates != NULL)
			candidate = flag->field->candidates;
		else if (flag->field->type->candidates != NULL)
			candidate = flag->field->type->candidates;
		if (candidate != NULL)
			printf(" <%s>", candidate);
		break;
	default:
		break;
	}

	printf("\n");

	return -ENOENT;
}

static void
print_config(struct rpki_config *config)
{
	pr_debug("Program configuration");
	pr_debug_add("{");
	pr_debug("%s: %s", "local-repository", config->local_repository);
	pr_debug("%s: %s", "tal", config->tal);
	pr_debug("%s: %s", "enable-rsync",
	    config->enable_rsync ? "true" : "false");
	pr_debug("%s: %s", "tal.shuffle-uris",
	    config->shuffle_uris ? "true" : "false");
	pr_debug("%s: %u", "tal.maximum-certificate-depth",
		    config->maximum_certificate_depth);
	pr_debug_rm("}");
}

static void
set_default_values(struct rpki_config *config)
{
	config->enable_rsync = true;
	config->local_repository = NULL;
	config->maximum_certificate_depth = 32;
	config->shuffle_uris = false;
	config->tal = NULL;
}

static void _print_usage(bool only_required)
{
	struct option_field *tmp;
	struct group_fields *tmp_all_fields;
	char *candidates;
	bool required;

	get_group_fields(&tmp_all_fields);

	while (tmp_all_fields->group_name != NULL) {
		tmp = tmp_all_fields->options;
		while(tmp->name != NULL) {
			required = tmp->required;

			if (only_required != required) {
				tmp += 1;
				continue;
			}

			fprintf(stderr, " ");

			if (!required)
				fprintf(stderr, "[");
			fprintf(stderr, "--%s", tmp->name);

			if (tmp->candidates != NULL)
				candidates = tmp->candidates;
			else if (tmp->type->candidates != NULL)
				candidates = tmp->type->candidates;
			else
				candidates = NULL;

			switch (tmp->has_arg) {
			case no_argument:
				break;
			case optional_argument:
				if(candidates == NULL)
					break;
				fprintf(stderr, "=<%s>", candidates);
				break;
			case required_argument:
				if(candidates == NULL)
					break;
				fprintf(stderr, " <%s>", candidates);
				break;
			default:
				break;
			}
			if (!required)
				fprintf(stderr, "]");
			tmp += 1;
		}
		tmp_all_fields += 1;
	}

}


void
print_usage(char *progname)
{
	/*
	 * TODO openbsd styleguide said use "getprogname" to set the progam
	 * name.
	 */
	fprintf(stderr, "usage: %s", progname);

	fprintf(stderr, " [-f <config_file>] "
	    "[--configuration-file <config_file>]");

	_print_usage(true);
	_print_usage(false);

	fprintf(stderr, "\n");
	exit(1);
}

int
handle_flags_config(int argc, char **argv)
{
	struct args_flag *flags;
	struct option *long_options;
	struct rpki_config config;
	int opt, indexptr, flags_len, error;

	set_default_values(&config);

	long_options = NULL;
	flags = NULL;
	flags_len = 0;

	error = construct_options(&flags, &long_options, &flags_len);
	if (error)
		return error; /* Error msg already printed. */

	while ((opt = getopt_long(argc, argv, "f:", long_options, &indexptr))
	    != -1)
		switch (opt) {
		case 0:
			flags[indexptr].is_set = true;
			error = handle_option(&config, flags[indexptr].field,
			    optarg);
			if (error) {
				print_usage(argv[0]);
				goto end;
			}
			break;
		case 'f':
			error = set_config_from_file(optarg, &config, flags);
			if (error) {
				print_usage(argv[0]);
				goto end;
			}
			break;
		default:
			print_usage(argv[0]);
			error = -EINVAL;
			goto end;
		}

	for (indexptr = 0; indexptr < flags_len; indexptr++)
		error |= check_missing_flags(&flags[indexptr]);

	if (error) {
		print_usage(argv[0]);
		goto end;
	}

	print_config(&config);
	config_set(&config);

end:
	if (error)
		_free_rpki_config(&config);

	free(flags);
	free(long_options);
	return error;

}

void
get_group_fields(struct group_fields **group_fields)
{
	if (group_fields)
		*group_fields = fields;
}

void
config_set(struct rpki_config *new)
{
	rpki_config = *new;
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
	return rpki_config.enable_rsync;
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

static void
_free_rpki_config(struct rpki_config *config)
{
	if (config->local_repository != NULL)
		free(config->local_repository);

	if (config->tal != NULL)
		free(config->tal);
}

void
free_rpki_config(void)
{
	_free_rpki_config(&rpki_config);
}
