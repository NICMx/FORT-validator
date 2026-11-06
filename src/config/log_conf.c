#include "config/log_conf.h"

#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>

#include "config/str.h"
#include "log.h"

#define LOG_LEVEL_VALUE_OFF "off"
#define LOG_LEVEL_VALUE_ERROR "error"
#define LOG_LEVEL_VALUE_WARNING "warning"
#define LOG_LEVEL_VALUE_INFO "info"
#define LOG_LEVEL_VALUE_DEBUG "debug"

static void
print_log_level(struct option_field const *field, void *value)
{
	struct log_level *lvl = value;
	char const *str = "<unknown>";

	switch (lvl->state) {
	case LLS_UNSET:
		break;
	case LLS_DISABLED:
		str = LOG_LEVEL_VALUE_OFF;
		break;
	case LLS_ENABLED:
		switch (lvl->val) {
		case LOG_ERR:
			str = LOG_LEVEL_VALUE_ERROR;
			break;
		case LOG_WARNING:
			str = LOG_LEVEL_VALUE_WARNING;
			break;
		case LOG_INFO:
			str = LOG_LEVEL_VALUE_INFO;
			break;
		case LOG_DEBUG:
			str = LOG_LEVEL_VALUE_DEBUG;
			break;
		}
		break;
	}

	pr_inf("%s: %s", field->name, str);
}

static int
parse_argv_log_level(struct option_field const *field, char const *str,
    void *result)
{
	struct log_level *lvl = result;

	lvl->state = LLS_ENABLED;

	if (strcmp(str, LOG_LEVEL_VALUE_OFF) == 0)
		lvl->state = LLS_DISABLED;
	else if (strcmp(str, LOG_LEVEL_VALUE_ERROR) == 0)
		lvl->val = LOG_ERR;
	else if (strcmp(str, LOG_LEVEL_VALUE_WARNING) == 0)
		lvl->val = LOG_WARNING;
	else if (strcmp(str, LOG_LEVEL_VALUE_INFO) == 0)
		lvl->val = LOG_INFO;
	else if (strcmp(str, LOG_LEVEL_VALUE_DEBUG) == 0)
		lvl->val = LOG_DEBUG;
	else
		return pr_err("Unknown %s: '%s'", field->name, str);

	return 0;
}

static int
parse_json_log_level(struct option_field const *opt, json_t *json,
    void *result)
{
	char const *string;
	int error;

	error = parse_json_string(json, opt->name, &string);
	return error ? error : parse_argv_log_level(opt, string, result);
}

const struct global_type gt_log_level = {
	.has_arg = required_argument,
	.size = sizeof(struct log_level),
	.print = print_log_level,
	.parse.argv = parse_argv_log_level,
	.parse.json = parse_json_log_level,
	.arg_doc = LOG_LEVEL_VALUE_OFF
	    "|" LOG_LEVEL_VALUE_ERROR
	    "|" LOG_LEVEL_VALUE_WARNING
	    "|" LOG_LEVEL_VALUE_INFO
	    "|" LOG_LEVEL_VALUE_DEBUG,
};
