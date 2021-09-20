#include "config/rrdp_conf.h"

#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include "config.h"
#include "log.h"
#include "config/boolean.h"
#include "config/uint.h"
#include "config/uint32.h"

/*
 * Note that this is just a wrapper to set rrdp.* arguments and its equivalent
 * http.* args.
 *
 * TODO (later) This wrapper will live until all rrdp.* args are fully
 * deprecated.
 */

#define DEREFERENCE_BOOL(void_value) (*((bool *) void_value))
#define DEREFERENCE_UINT32(void_value) (*((uint32_t *) void_value))
#define DEREFERENCE_UINT(void_value) (*((unsigned int *) void_value))

static int
set_rrdp_enabled(char const *name, bool value)
{
	/* Warn about future deprecation */
	if (strcmp(name, "rrdp.enabled") == 0)
		pr_op_warn("'rrdp.enabled' is deprecated; use 'http.enabled' instead.");

	config_set_rrdp_enabled(value);
	config_set_http_enabled(value);
	return 0;
}

static int
set_priority(char const *name, uint32_t value)
{
	/* Warn about future deprecation */
	if (strcmp(name, "rrdp.priority") == 0)
		pr_op_warn("'rrdp.priority' is deprecated; use 'http.priority' instead.");

	config_set_rrdp_priority(value);
	config_set_http_priority(value);
	return 0;
}

static int
set_retry_count(char const *name, unsigned int value)
{
	/* Warn about future deprecation */
	if (strcmp(name, "rrdp.retry.count") == 0)
		pr_op_warn("'rrdp.retry.count' is deprecated; use 'http.retry.count' instead.");

	config_set_rrdp_retry_count(value);
	config_set_http_retry_count(value);
	return 0;
}

static int
set_retry_interval(char const *name, unsigned int value)
{
	/* Warn about future deprecation */
	if (strcmp(name, "rrdp.retry.interval") == 0)
		pr_op_warn("'rrdp.retry.interval' is deprecated; use 'http.retry.interval' instead.");

	config_set_rrdp_retry_interval(value);
	config_set_http_retry_interval(value);
	return 0;
}

int
parse_argv_enabled(struct option_field const *field, char const *str,
    void *result)
{
	int error;

	error = parse_argv_bool(field, str, result);
	if (error)
		return error;

	return set_rrdp_enabled(field->name, DEREFERENCE_BOOL(result));
}

int
parse_json_enabled(struct option_field const *opt, struct json_t *json,
    void *result)
{
	int error;

	error = parse_json_bool(opt, json, result);
	if (error)
		return error;

	return set_rrdp_enabled(opt->name, DEREFERENCE_BOOL(result));
}

int
parse_argv_priority(struct option_field const *field, char const *str,
    void *result)
{
	int error;

	error = parse_argv_uint32(field, str, result);
	if (error)
		return error;

	return set_priority(field->name, DEREFERENCE_UINT32(result));
}

int
parse_json_priority(struct option_field const *opt, json_t *json, void *result)
{
	int error;

	error = parse_json_uint32(opt, json, result);
	if (error)
		return error;

	return set_priority(opt->name, DEREFERENCE_UINT32(result));
}

int
parse_argv_retry_count(struct option_field const *field, char const *str,
    void *result)
{
	int error;

	error = parse_argv_uint(field, str, result);
	if (error)
		return error;

	return set_retry_count(field->name, DEREFERENCE_UINT(result));
}

int
parse_json_retry_count(struct option_field const *opt, json_t *json,
    void *result)
{
	int error;

	error = parse_json_uint(opt, json, result);
	if (error)
		return error;

	return set_retry_count(opt->name, DEREFERENCE_UINT(result));
}

int
parse_argv_retry_interval(struct option_field const *field, char const *str,
    void *result)
{
	int error;

	error = parse_argv_uint(field, str, result);
	if (error)
		return error;

	return set_retry_interval(field->name, DEREFERENCE_UINT(result));
}

int
parse_json_retry_interval(struct option_field const *opt, json_t *json,
    void *result)
{
	int error;

	error = parse_json_uint(opt, json, result);
	if (error)
		return error;

	return set_retry_interval(opt->name, DEREFERENCE_UINT(result));
}

const struct global_type gt_rrdp_enabled = {
	.has_arg = optional_argument,
	.size = sizeof(bool),
	.print = print_bool,
	.parse.argv = parse_argv_enabled,
	.parse.json = parse_json_enabled,
	.arg_doc = "true|false",
};

const struct global_type gt_rrdp_priority = {
	.has_arg = required_argument,
	.size = sizeof(uint32_t),
	.print = print_uint32,
	.parse.argv = parse_argv_priority,
	.parse.json = parse_json_priority,
	.arg_doc = "<32-bit unsigned integer>",
};

const struct global_type gt_rrdp_retry_count = {
	.has_arg = required_argument,
	.size = sizeof(unsigned int),
	.print = print_uint,
	.parse.argv = parse_argv_retry_count,
	.parse.json = parse_json_retry_count,
	.arg_doc = "<unsigned integer>",
};

const struct global_type gt_rrdp_retry_interval = {
	.has_arg = required_argument,
	.size = sizeof(unsigned int),
	.print = print_uint,
	.parse.argv = parse_argv_retry_interval,
	.parse.json = parse_json_retry_interval,
	.arg_doc = "<unsigned integer>",
};
