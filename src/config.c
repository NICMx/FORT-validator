#include "config.h"

#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <getopt.h>

#include "common.h"
#include "log.h"

#define OPT_FIELD_ARRAY_LEN(array) ARRAY_LEN(array) - 1

struct args_flag {
	struct option_field *field;
	bool is_set;
};

static int parse_bool(struct option_field *, char *, void *);
static int parse_u_int(struct option_field *, char *, void *);

static struct rpki_config config;

static struct global_type gt_bool = {
	.id = GTI_BOOL,
	.name = "Boolean",
	.size = sizeof(bool),
	.parse = parse_bool,
	.candidates = "true false",
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
	.candidates = "Unsigned Int",
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
		 * It cannot be UINT_MAX, because then the actual number will overflow
		 * and will never be bigger than this.
		 */
		.max = 	UINT_MAX - 1,
		.required = false,
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
	case required_argument:
	case optional_argument:
		if (field->has_arg == optional_argument && str == NULL) {
			*value = true;
			return 0;
		}
		/**
		 * XXX: (fine) GETOPT should had ensure that the code did
		 * not reach here for this particular case.
		 * */
		return str_to_bool(str, result);
		break;
	}

	if (str == NULL) {
		*value = true;
		return 0;
	}

	return str_to_bool(str, result);
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
	struct args_flag *result_flags;
	struct option_field *global, *tal;
	struct option *result_options;
	unsigned int global_len, tal_len, total_len, i, result_idx;

	get_global_fields(&global, &global_len);
	get_tal_fields(&tal, &tal_len);

	total_len = global_len + tal_len;

	result_flags = calloc(total_len, sizeof(struct args_flag));
	if (result_flags == NULL)
		return pr_enomem();

	/* Long options must end with zeros (+1) */
	result_options = calloc(total_len + 1, sizeof(struct option));
	if (result_options == NULL) {
		free(result_flags);
		return pr_enomem();
	}

	result_idx = 0;
	for(i = 0; i < global_len; i++) {
		result_flags[result_idx].field = &(global[i]);

		result_options[result_idx].name = global[i].name;
		result_options[result_idx].has_arg = global[i].has_arg;
		result_options[result_idx].val = global[i].short_opt;
		result_options[result_idx].flag = NULL;

		result_idx++;
	}

	for(i = 0; i < tal_len; i++) {
		result_flags[result_idx].field = &(tal[i]);

		result_options[result_idx].name = tal[i].name;
		result_options[result_idx].has_arg = tal[i].has_arg;
		result_options[result_idx].val = tal[i].short_opt;
		result_options[result_idx].flag = NULL;

		result_idx++;
	}

	*flags = result_flags;
	*flags_len = total_len;
	*long_options = result_options;

	return 0;
}

static void
set_string(void **field, char *str)
{
	*field = str;
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
		set_string(config_param, str);
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

	printf("Missing flag --%s", flag->field->name);
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

int
handle_flags_config(int argc, char **argv, struct rpki_config *config)
{
	struct args_flag *flags;
	struct option *long_options;
	int opt, indexptr, flags_len, error = 0;

	flags = NULL;
	long_options = NULL;

	error = construct_options(&flags, &long_options, &flags_len);
	if (error)
		return error; /* Error msg already printed. */

	while ((opt = getopt_long(argc, argv, "", long_options, &indexptr))
	    != -1) {
		switch (opt) {
		case 0:
			flags[indexptr].is_set = true;
			error = handle_option(config, flags[indexptr].field,
			    optarg);
			break;
		default:
			error = pr_err("some usage hints.");/* TODO */
			break;
		}

		if (error)
			goto end;
	}

	for (indexptr = 0; indexptr < flags_len; indexptr++) {
		error |= check_missing_flags(&flags[indexptr]);
	}

	print_config(config);

end:
	free(flags);
	free(long_options);
	return error;

}

void
get_global_fields(struct option_field **fields, unsigned int *len)
{
	if (fields)
		*fields = global_fields;
	if (len)
		*len = OPT_FIELD_ARRAY_LEN(global_fields);
}

void
get_tal_fields(struct option_field **fields, unsigned int *len)
{
	if (fields)
		*fields = tal_fields;
	if (len)
		*len = OPT_FIELD_ARRAY_LEN(tal_fields);
}

void
config_set(struct rpki_config *new)
{
	config = *new;
}

char const *
config_get_tal(void)
{
	return config.tal;
}

char const *
config_get_local_repository(void)
{
	return config.local_repository;
}

bool
config_get_enable_rsync(void)
{
	return config.enable_rsync;
}

bool
config_get_shuffle_uris(void)
{
	return config.shuffle_uris;
}

unsigned int
config_get_max_cert_depth(void)
{
	return config.maximum_certificate_depth;
}
