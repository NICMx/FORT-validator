#include "config/log_conf.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <syslog.h>

#include "log.h"
#include "config/str.h"

#define LOG_LEVEL_VALUE_ERROR "error"
#define LOG_LEVEL_VALUE_WARNING "warning"
#define LOG_LEVEL_VALUE_INFO "info"
#define LOG_LEVEL_VALUE_DEBUG "debug"

#define LOG_OUTPUT_VALUE_SYSLOG "syslog"
#define LOG_OUTPUT_VALUE_CONSOLE "console"

#define LOG_FACILITY_VALUE_AUTH "auth"
#define LOG_FACILITY_VALUE_AUTHPRIV "authpriv"
#define LOG_FACILITY_VALUE_CRON "cron"
#define LOG_FACILITY_VALUE_DAEMON "daemon"
#define LOG_FACILITY_VALUE_FTP "ftp"
#define LOG_FACILITY_VALUE_KERN "kern"
#define LOG_FACILITY_VALUE_LPR "lpr"
#define LOG_FACILITY_VALUE_MAIL "mail"
#define LOG_FACILITY_VALUE_NEWS "news"
#define LOG_FACILITY_VALUE_SYSLOG "syslog"
#define LOG_FACILITY_VALUE_USER "user"
#define LOG_FACILITY_VALUE_UUCP "uucp"
#define LOG_FACILITY_VALUE_LOCAL0 "local0"
#define LOG_FACILITY_VALUE_LOCAL1 "local1"
#define LOG_FACILITY_VALUE_LOCAL2 "local2"
#define LOG_FACILITY_VALUE_LOCAL3 "local3"
#define LOG_FACILITY_VALUE_LOCAL4 "local4"
#define LOG_FACILITY_VALUE_LOCAL5 "local5"
#define LOG_FACILITY_VALUE_LOCAL6 "local6"
#define LOG_FACILITY_VALUE_LOCAL7 "local7"

#define DEREFERENCE_UINT(void_value) (*((uint8_t *) void_value))
#define DEREFERENCE_ENUM(void_value) (*((enum log_output *) void_value))
#define DEREFERENCE_UINT32(void_value) (*((uint32_t *) void_value))

static void
print_log_level(struct option_field const *field, void *value)
{
	char const *str = "<unknown>";

	switch (DEREFERENCE_UINT(value)) {
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

	pr_op_info("%s: %s", field->name, str);
}

static void
print_log_output(struct option_field const *field, void *value)
{
	char const *str = "<unknown>";

	switch (DEREFERENCE_ENUM(value)) {
	case SYSLOG:
		str = LOG_OUTPUT_VALUE_SYSLOG;
		break;
	case CONSOLE:
		str = LOG_OUTPUT_VALUE_CONSOLE;
		break;
	}

	pr_op_info("%s: %s", field->name, str);
}

static void
print_log_facility(struct option_field const *field, void *value)
{
	char const *str = "<unknown>";

	switch (DEREFERENCE_UINT32(value)) {
	case LOG_USER:
		str = LOG_FACILITY_VALUE_USER;
		break;
	case LOG_MAIL:
		str = LOG_FACILITY_VALUE_MAIL;
		break;
	case LOG_DAEMON:
		str = LOG_FACILITY_VALUE_DAEMON;
		break;
	case LOG_AUTH:
		str = LOG_FACILITY_VALUE_AUTH;
		break;
	case LOG_LPR:
		str = LOG_FACILITY_VALUE_LPR;
		break;
	case LOG_NEWS:
		str = LOG_FACILITY_VALUE_NEWS;
		break;
	case LOG_UUCP:
		str = LOG_FACILITY_VALUE_UUCP;
		break;
	case LOG_CRON:
		str = LOG_FACILITY_VALUE_CRON;
		break;
	case LOG_AUTHPRIV:
		str = LOG_FACILITY_VALUE_AUTHPRIV;
		break;
	case LOG_FTP:
		str = LOG_FACILITY_VALUE_FTP;
		break;
	case LOG_LOCAL0:
		str = LOG_FACILITY_VALUE_LOCAL0;
		break;
	case LOG_LOCAL1:
		str = LOG_FACILITY_VALUE_LOCAL1;
		break;
	case LOG_LOCAL2:
		str = LOG_FACILITY_VALUE_LOCAL2;
		break;
	case LOG_LOCAL3:
		str = LOG_FACILITY_VALUE_LOCAL3;
		break;
	case LOG_LOCAL4:
		str = LOG_FACILITY_VALUE_LOCAL4;
		break;
	case LOG_LOCAL5:
		str = LOG_FACILITY_VALUE_LOCAL5;
		break;
	case LOG_LOCAL6:
		str = LOG_FACILITY_VALUE_LOCAL6;
		break;
	case LOG_LOCAL7:
		str = LOG_FACILITY_VALUE_LOCAL7;
		break;
	}

	pr_op_info("%s: %s", field->name, str);
}

static int
parse_argv_log_level(struct option_field const *field, char const *str,
    void *result)
{
	if (strcmp(str, LOG_LEVEL_VALUE_ERROR) == 0)
		DEREFERENCE_UINT(result) = LOG_ERR;
	else if (strcmp(str, LOG_LEVEL_VALUE_WARNING) == 0)
		DEREFERENCE_UINT(result) = LOG_WARNING;
	else if (strcmp(str, LOG_LEVEL_VALUE_INFO) == 0)
		DEREFERENCE_UINT(result) = LOG_INFO;
	else if (strcmp(str, LOG_LEVEL_VALUE_DEBUG) == 0)
		DEREFERENCE_UINT(result) = LOG_DEBUG;
	else
		return pr_op_err("Unknown %s: '%s'", field->name, str);

	return 0;
}

static int
parse_argv_log_output(struct option_field const *field, char const *str,
    void *result)
{
	if (strcmp(str, LOG_OUTPUT_VALUE_SYSLOG) == 0)
		DEREFERENCE_ENUM(result) = SYSLOG;
	else if (strcmp(str, LOG_OUTPUT_VALUE_CONSOLE) == 0)
		DEREFERENCE_ENUM(result) = CONSOLE;
	else
		return pr_op_err("Unknown %s: '%s'", field->name, str);

	return 0;
}

static int
parse_argv_log_facility(struct option_field const *field, char const *str,
    void *result)
{
	if (strcmp(str, LOG_FACILITY_VALUE_AUTH) == 0)
		DEREFERENCE_UINT32(result) = LOG_AUTH;
	else if (strcmp(str, LOG_FACILITY_VALUE_AUTHPRIV) == 0)
		DEREFERENCE_UINT32(result) = LOG_AUTHPRIV;
	else if (strcmp(str, LOG_FACILITY_VALUE_CRON) == 0)
		DEREFERENCE_UINT32(result) = LOG_CRON;
	else if (strcmp(str, LOG_FACILITY_VALUE_DAEMON) == 0)
		DEREFERENCE_UINT32(result) = LOG_DAEMON;
	else if (strcmp(str, LOG_FACILITY_VALUE_FTP) == 0)
		DEREFERENCE_UINT32(result) = LOG_FTP;
	else if (strcmp(str, LOG_FACILITY_VALUE_LPR) == 0)
		DEREFERENCE_UINT32(result) = LOG_LPR;
	else if (strcmp(str, LOG_FACILITY_VALUE_MAIL) == 0)
		DEREFERENCE_UINT32(result) = LOG_MAIL;
	else if (strcmp(str, LOG_FACILITY_VALUE_NEWS) == 0)
		DEREFERENCE_UINT32(result) = LOG_NEWS;
	else if (strcmp(str, LOG_FACILITY_VALUE_USER) == 0)
		DEREFERENCE_UINT32(result) = LOG_USER;
	else if (strcmp(str, LOG_FACILITY_VALUE_UUCP) == 0)
		DEREFERENCE_UINT32(result) = LOG_UUCP;
	else if (strcmp(str, LOG_FACILITY_VALUE_LOCAL0) == 0)
		DEREFERENCE_UINT32(result) = LOG_LOCAL0;
	else if (strcmp(str, LOG_FACILITY_VALUE_LOCAL1) == 0)
		DEREFERENCE_UINT32(result) = LOG_LOCAL1;
	else if (strcmp(str, LOG_FACILITY_VALUE_LOCAL2) == 0)
		DEREFERENCE_UINT32(result) = LOG_LOCAL2;
	else if (strcmp(str, LOG_FACILITY_VALUE_LOCAL3) == 0)
		DEREFERENCE_UINT32(result) = LOG_LOCAL3;
	else if (strcmp(str, LOG_FACILITY_VALUE_LOCAL4) == 0)
		DEREFERENCE_UINT32(result) = LOG_LOCAL4;
	else if (strcmp(str, LOG_FACILITY_VALUE_LOCAL5) == 0)
		DEREFERENCE_UINT32(result) = LOG_LOCAL5;
	else if (strcmp(str, LOG_FACILITY_VALUE_LOCAL6) == 0)
		DEREFERENCE_UINT32(result) = LOG_LOCAL6;
	else if (strcmp(str, LOG_FACILITY_VALUE_LOCAL7) == 0)
		DEREFERENCE_UINT32(result) = LOG_LOCAL7;
	else if (strcmp(str, LOG_FACILITY_VALUE_KERN) == 0 ||
	    strcmp(str, LOG_FACILITY_VALUE_SYSLOG) == 0)
		return pr_op_err("Unsupported %s: '%s', use another value",
		    field->name, str);
	else
		return pr_op_err("Unknown %s: '%s'", field->name, str);

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

static int
parse_json_log_output(struct option_field const *opt, json_t *json,
    void *result)
{
	char const *string;
	int error;

	error = parse_json_string(json, opt->name, &string);
	return error ? error : parse_argv_log_output(opt, string, result);
}

static int
parse_json_log_facility(struct option_field const *opt, json_t *json,
    void *result)
{
	char const *string;
	int error;

	error = parse_json_string(json, opt->name, &string);
	return error ? error : parse_argv_log_facility(opt, string, result);
}

const struct global_type gt_log_level = {
	.has_arg = required_argument,
	.size = sizeof(uint8_t),
	.print = print_log_level,
	.parse.argv = parse_argv_log_level,
	.parse.json = parse_json_log_level,
	.arg_doc = LOG_LEVEL_VALUE_ERROR
	    "|" LOG_LEVEL_VALUE_WARNING
	    "|" LOG_LEVEL_VALUE_INFO
	    "|" LOG_LEVEL_VALUE_DEBUG,
};

const struct global_type gt_log_output = {
	.has_arg = required_argument,
	.size = sizeof(enum log_output),
	.print = print_log_output,
	.parse.argv = parse_argv_log_output,
	.parse.json = parse_json_log_output,
	.arg_doc = LOG_OUTPUT_VALUE_SYSLOG "|" LOG_OUTPUT_VALUE_CONSOLE,
};

const struct global_type gt_log_facility = {
	.has_arg = required_argument,
	.size = sizeof(uint32_t),
	.print = print_log_facility,
	.parse.argv = parse_argv_log_facility,
	.parse.json = parse_json_log_facility,
	.arg_doc = LOG_FACILITY_VALUE_AUTH
	    "|" LOG_FACILITY_VALUE_AUTHPRIV
	    "|" LOG_FACILITY_VALUE_CRON
	    "|" LOG_FACILITY_VALUE_DAEMON
	    "|" LOG_FACILITY_VALUE_FTP
	    "|" LOG_FACILITY_VALUE_LPR
	    "|" LOG_FACILITY_VALUE_MAIL
	    "|" LOG_FACILITY_VALUE_NEWS
	    "|" LOG_FACILITY_VALUE_USER
	    "|" LOG_FACILITY_VALUE_UUCP
	    "|" LOG_FACILITY_VALUE_LOCAL0
	    "|" LOG_FACILITY_VALUE_LOCAL1
	    "|" LOG_FACILITY_VALUE_LOCAL2
	    "|" LOG_FACILITY_VALUE_LOCAL3
	    "|" LOG_FACILITY_VALUE_LOCAL4
	    "|" LOG_FACILITY_VALUE_LOCAL5
	    "|" LOG_FACILITY_VALUE_LOCAL6
	    "|" LOG_FACILITY_VALUE_LOCAL7,
};
