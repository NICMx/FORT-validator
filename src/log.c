#include "log.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <syslog.h>
#include <time.h>

#include "config.h"
#include "debug.h"
#include "thread_var.h"

struct level {
	char const *label;
	char const *color;
	FILE *stream;
};

static struct level DBG = { "DBG", "\x1B[36m" };
static struct level INF = { "INF", "\x1B[37m" };
static struct level WRN = { "WRN", "\x1B[33m" };
static struct level ERR = { "ERR", "\x1B[31m" };
static struct level CRT = { "CRT", "\x1B[35m" };
static struct level UNK = { "UNK", "" };
#define COLOR_RESET "\x1B[0m"

struct log_config {
	bool fprintf_enabled; /* Print on the standard streams? */
	bool syslog_enabled; /* Print on syslog? */

	uint8_t level;
	char const *prefix;
	bool color;
	int facility;
};

/* Configuration for the operation logs. */
static struct log_config op_config;
/* Configuration for the validation logs. */
static struct log_config val_config;

static void init_config(struct log_config *cfg)
{
	cfg->fprintf_enabled = true;
	cfg->syslog_enabled = true;
	cfg->level = LOG_DEBUG;
	cfg->prefix = NULL;
	cfg->color = false;
	cfg->facility = LOG_DAEMON;
}

void
log_setup(void)
{
	DBG.stream = stdout;
	INF.stream = stdout;
	WRN.stream = stderr;
	ERR.stream = stderr;
	CRT.stream = stderr;
	UNK.stream = stdout;

	openlog("fort", LOG_CONS | LOG_PID, LOG_DAEMON);

	init_config(&op_config);
	init_config(&val_config);
}

static void
log_disable_syslog(void)
{
	if (op_config.syslog_enabled || val_config.syslog_enabled) {
		closelog();
		op_config.syslog_enabled = false;
		val_config.syslog_enabled = false;
	}
}

void
log_start(void)
{
	if (config_get_val_log_enabled()) {
		switch (config_get_val_log_output()) {
		case SYSLOG:
			pr_op_info("Syslog log output configured; disabling validation logging on standard streams.");
			pr_op_info("(Validation Logs will be sent to syslog only.)");
			val_config.fprintf_enabled = false;
			break;
		case CONSOLE:
			pr_op_info("Console log output configured; disabling validation logging on syslog.");
			pr_op_info("(Validation Logs will be sent to the standard streams only.)");
			val_config.syslog_enabled = false;
			break;
		}
	} else {
		pr_op_info("Disabling validation logging on syslog.");
		pr_op_info("Disabling validation logging on standard streams.");
		val_config.fprintf_enabled = false;
		val_config.syslog_enabled = false;
	}

	if (config_get_op_log_enabled()) {
		switch (config_get_op_log_output()) {
		case SYSLOG:
			pr_op_info("Syslog log output configured; disabling operation logging on standard streams.");
			pr_op_info("(Operation Logs will be sent to syslog only.)");
			op_config.fprintf_enabled = false;
			break;
		case CONSOLE:
			pr_op_info("Console log output configured; disabling operation logging on syslog.");
			pr_op_info("(Operation Logs will be sent to the standard streams only.)");
			if (val_config.syslog_enabled)
				op_config.syslog_enabled = false;
			else
				log_disable_syslog();
			break;
		}
	} else {
		pr_op_info("Disabling operation logging on syslog.");
		pr_op_info("Disabling operation logging on standard streams.");
		op_config.fprintf_enabled = false;
		if (val_config.syslog_enabled)
			op_config.syslog_enabled = false;
		else
			log_disable_syslog();
	}

	op_config.level = config_get_op_log_level();
	op_config.prefix = config_get_op_log_tag();
	op_config.color = config_get_op_log_color_output();
	op_config.facility = config_get_op_log_facility();
	val_config.level = config_get_val_log_level();
	val_config.prefix = config_get_val_log_tag();
	val_config.color = config_get_val_log_color_output();
	val_config.facility = config_get_val_log_facility();
}

void
log_teardown(void)
{
	log_disable_syslog();
}

void
log_flush(void)
{
	if (op_config.fprintf_enabled || val_config.fprintf_enabled) {
		fflush(stdout);
		fflush(stderr);
	}
}

bool
log_val_enabled(unsigned int level)
{
	return val_config.level >= level;
}

bool
log_op_enabled(unsigned int level)
{
	return op_config.level >= level;
}

static struct level const *
level2struct(int level)
{
	switch (level) {
	case LOG_CRIT:
		return &CRT;
	case LOG_ERR:
		return &ERR;
	case LOG_WARNING:
		return &WRN;
	case LOG_INFO:
		return &INF;
	case LOG_DEBUG:
		return &DBG;
	}

	return &UNK;
}

static void
__vfprintf(int level, struct log_config *cfg, char const *format, va_list args)
{
	char time_buff[20];
	struct level const *lvl;
	time_t now;
	struct tm stm_buff;
	char const *file_name;

	lvl = level2struct(level);

	if (cfg->color)
		fprintf(lvl->stream, "%s", lvl->color);

	now = time(0);
	if (now != ((time_t) -1)) {
		localtime_r(&now, &stm_buff);
		strftime(time_buff, sizeof(time_buff), "%b %e %T", &stm_buff);
		fprintf(lvl->stream, "%s ", time_buff);
	}

	fprintf(lvl->stream, "%s", lvl->label);
	if (cfg->prefix)
		fprintf(lvl->stream, " [%s]", cfg->prefix);
	fprintf(lvl->stream, ": ");

	file_name = fnstack_peek();
	if (file_name != NULL)
		fprintf(lvl->stream, "%s: ", file_name);

	vfprintf(lvl->stream, format, args);

	if (cfg->color)
		fprintf(lvl->stream, COLOR_RESET);
	fprintf(lvl->stream, "\n");

	/* Force flush */
	if (lvl->stream == stdout)
		fflush(lvl->stream);
}

#define MSG_LEN 512

static void
__syslog(int level, struct log_config *cfg, const char *format, va_list args)
{
	char const *file_name;
	struct level const *lvl;
	char msg[MSG_LEN];

	file_name = fnstack_peek();
	lvl = level2struct(level);

	/* Can't use vsyslog(); it's not portable. */
	vsnprintf(msg, MSG_LEN, format, args);
	if (file_name != NULL) {
		if (cfg->prefix != NULL)
			syslog(level | cfg->facility, "%s [%s]: %s: %s",
			    lvl->label, cfg->prefix, file_name, msg);
		else
			syslog(level | cfg->facility, "%s: %s: %s",
			    lvl->label, file_name, msg);
	} else {
		if (cfg->prefix != NULL)
			syslog(level | cfg->facility, "%s [%s]: %s",
			    lvl->label, cfg->prefix, msg);
		else
			syslog(level | cfg->facility, "%s: %s",
			    lvl->label, msg);
	}
}

#define PR_SIMPLE(lvl, config)						\
	do {								\
		va_list args;						\
									\
		if (lvl > config.level)					\
			break;						\
									\
		if (config.syslog_enabled) {				\
			va_start(args, format);				\
			__syslog(lvl, &config, format, args);		\
			va_end(args);					\
		}							\
									\
		if (config.fprintf_enabled) {				\
			va_start(args, format);				\
			__vfprintf(lvl, &config, format, args);		\
			va_end(args);					\
		}							\
	} while (0)

void
pr_op_debug(const char *format, ...)
{
	PR_SIMPLE(LOG_DEBUG, op_config);
}

void
pr_op_info(const char *format, ...)
{
	PR_SIMPLE(LOG_INFO, op_config);
}

/**
 * Always returs 0. (So you can interrupt whatever you're doing without failing
 * validation.)
 */
int
pr_op_warn(const char *format, ...)
{
	PR_SIMPLE(LOG_WARNING, op_config);
	return 0;
}

int
__pr_op_err(int error, const char *format, ...)
{
	PR_SIMPLE(LOG_ERR, op_config);
	return error;
}

void
pr_val_debug(const char *format, ...)
{
	PR_SIMPLE(LOG_DEBUG, val_config);
}

void
pr_val_info(const char *format, ...)
{
	PR_SIMPLE(LOG_INFO, val_config);
}

/**
 * Always returs 0. (So you can interrupt whatever you're doing without failing
 * validation.)
 */
int
pr_val_warn(const char *format, ...)
{
	PR_SIMPLE(LOG_WARNING, val_config);
	return 0;
}

int
__pr_val_err(int error, const char *format, ...)
{
	PR_SIMPLE(LOG_ERR, val_config);
	return error;
}

struct crypto_cb_arg {
	unsigned int stack_size;
	int (*error_fn)(int, const char *, ...);
};

static int
log_crypto_error(const char *str, size_t len, void *_arg)
{
	struct crypto_cb_arg *arg = _arg;
	arg->error_fn(0, "-> %s", str);
	arg->stack_size++;
	return 1;
}

static int
crypto_err(struct log_config *cfg, int (*error_fn)(int, const char *, ...))
{
	struct crypto_cb_arg arg;

	error_fn(0, "libcrypto error stack:");

	arg.stack_size = 0;
	arg.error_fn = error_fn;
	ERR_print_errors_cb(log_crypto_error, &arg);
	if (arg.stack_size == 0)
		error_fn(0,  "   <Empty>");

	return -EINVAL;
}

/**
 * This is like pr_err() and pr_errno(), except meant to log an error made
 * during a libcrypto routine.
 *
 * This differs from usual printf-like functions:
 *
 * - It returns -EINVAL, not bytes written.
 * - It prints a newline.
 * - Also prints the cryptolib's error message stack.
 *
 * Always appends a newline at the end.
 */
int
op_crypto_err(const char *format, ...)
{
	PR_SIMPLE(LOG_ERR, op_config);
	return crypto_err(&op_config, __pr_op_err);
}

/**
 * This is like pr_err() and pr_errno(), except meant to log an error made
 * during a libcrypto routine.
 *
 * This differs from usual printf-like functions:
 *
 * - It returns -EINVAL, not bytes written.
 * - It prints a newline.
 * - Also prints the cryptolib's error message stack.
 *
 * Always appends a newline at the end.
 */
int
val_crypto_err(const char *format, ...)
{
	PR_SIMPLE(LOG_ERR, val_config);
	return crypto_err(&val_config, __pr_val_err);
}

/**
 * This is an operation log
 **/
int
pr_enomem(void)
{
	pr_op_err("Out of memory.");
	print_stack_trace();
	exit(ENOMEM);
}

/**
 * This is an operation log
 **/
__dead void
pr_crit(const char *format, ...)
{
	PR_SIMPLE(LOG_CRIT, op_config);
	print_stack_trace();
	exit(-1);
}

/**
 * Prints the [format, ...] error message using the configured logging severity
 * of the @id incidence.
 */
int
incidence(enum incidence_id id, const char *format, ...)
{
	enum incidence_action action;

	action = incidence_get_action(id);
	switch (action) {
	case INAC_IGNORE:
		return 0;
	case INAC_WARN:
		PR_SIMPLE(LOG_WARNING, val_config);
		return 0;
	case INAC_ERROR:
		PR_SIMPLE(LOG_ERR, val_config);
		return -EINVAL;
	}

	pr_crit("Unknown incidence action: %u", action);
}
