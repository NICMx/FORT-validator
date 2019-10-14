#include "log.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <syslog.h>

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

/* LOG_PERROR is not portable, apparently, so I implemented it myself */
static bool fprintf_enabled;
static bool syslog_enabled;

void
log_setup(void)
{
	/* =_= */
	DBG.stream = stdout;
	INF.stream = stdout;
	WRN.stream = stderr;
	ERR.stream = stderr;
	CRT.stream = stderr;
	UNK.stream = stdout;

	openlog("fort", LOG_CONS | LOG_PID, LOG_DAEMON);
	fprintf_enabled = true;
	syslog_enabled = true;
}

static void
log_disable_std(void)
{
	fprintf_enabled = false;
}

static void
log_disable_syslog(void)
{
	if (syslog_enabled) {
		closelog();
		syslog_enabled = false;
	}
}

void
log_start(void)
{
	switch (config_get_log_output()) {
	case SYSLOG:
		pr_info("Syslog log output configured; disabling logging on standard streams.");
		pr_info("(Logs will be sent to syslog only.)");
		log_disable_std();
		break;
	case CONSOLE:
		pr_info("Console log output configured; disabling logging on syslog.");
		pr_info("(Logs will be sent to the standard streams only.)");
		log_disable_syslog();
		break;
	}
}

void
log_teardown(void)
{
	log_disable_std();
	log_disable_syslog();
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
__fprintf(int level, char const *format, ...)
{
	struct level const *lvl;
	va_list args;

	lvl = level2struct(level);

	if (config_get_color_output())
		fprintf(lvl->stream, "%s", lvl->color);

	fprintf(lvl->stream, "%s: ", lvl->label);
	va_start(args, format);
	vfprintf(lvl->stream, format, args);
	va_end(args);

	if (config_get_color_output())
		fprintf(lvl->stream, COLOR_RESET);

	fprintf(lvl->stream, "\n");
}

#define MSG_LEN 512

static void
pr_syslog(int level, const char *format, va_list args)
{
	char const *file_name;
	struct level const *lvl;
	char msg[MSG_LEN];

	file_name = fnstack_peek();
	lvl = level2struct(level);

	/* Can't use vsyslog(); it's not portable. */
	vsnprintf(msg, MSG_LEN, format, args);
	if (file_name != NULL)
		syslog(level, "%s: %s: %s", lvl->label, file_name, msg);
	else
		syslog(level, "%s: %s", lvl->label, msg);
}

static void
pr_stream(int level, const char *format, va_list args)
{
	char const *file_name;
	struct level const *lvl;

	file_name = fnstack_peek();
	lvl = level2struct(level);

	if (config_get_color_output())
		fprintf(lvl->stream, "%s", lvl->color);

	fprintf(lvl->stream, "%s: ", lvl->label);
	if (file_name != NULL)
		fprintf(lvl->stream, "%s: ", file_name);
	vfprintf(lvl->stream, format, args);

	if (config_get_color_output())
		fprintf(lvl->stream, "%s", COLOR_RESET);

	fprintf(lvl->stream, "\n");
}

#define PR_SIMPLE(level)						\
	do {								\
		va_list args;						\
									\
		if (level > config_get_log_level())			\
			break;						\
									\
		if (syslog_enabled) {					\
			va_start(args, format);				\
			pr_syslog(level, format, args);			\
			va_end(args);					\
		}							\
									\
		if (fprintf_enabled) {					\
			va_start(args, format);				\
			pr_stream(level, format, args);			\
			va_end(args);					\
		}							\
	} while (0)

bool
log_debug_enabled(void)
{
	return config_get_log_level() == LOG_DEBUG;
}

void
pr_debug(const char *format, ...)
{
	PR_SIMPLE(LOG_DEBUG);
}

void
pr_info(const char *format, ...)
{
	PR_SIMPLE(LOG_INFO);
}

/**
 * Always appends a newline at the end. Always returs 0. (So you can interrupt
 * whatever you're doing without failing validation.)
 */
int
pr_warn(const char *format, ...)
{
	PR_SIMPLE(LOG_WARNING);
	return 0;
}

/**
 * Always appends a newline at the end. Always returs -EINVAL.
 */
int
pr_err(const char *format, ...)
{
	PR_SIMPLE(LOG_ERR);
	return -EINVAL;
}

/**
 * @error fulfills two functions, both of which apply only if it's nonzero:
 *
 * - @error's corresponding generic error message will be appended to the print.
 * - @error's value will be returned. This is for the sake of error code
 *   propagation.
 *
 * If @error is zero, no error message will be appended, and the function will
 * return -EINVAL. (I acknowledge that this looks convoluted at first glance.
 * The purpose is to ensure that this function will propagate an error code even
 * if there is no error code originally.)
 *
 * Always appends a newline at the end.
 */
int
pr_errno(int error, const char *format, ...)
{
	PR_SIMPLE(LOG_ERR);

	if (!error)
		return -EINVAL;

	if (syslog_enabled)
		syslog(LOG_ERR, "  - %s", strerror(error));
	if (fprintf_enabled)
		__fprintf(LOG_ERR, "  - %s", strerror(error));

	return error;
}

static int log_crypto_error(const char *str, size_t len, void *arg)
{
	if (syslog_enabled)
		syslog(LOG_ERR, "  - %s", str);
	if (fprintf_enabled)
		__fprintf(LOG_ERR, "  - %s", str);
	return 1;
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
crypto_err(const char *format, ...)
{
	unsigned int stack_size;

	PR_SIMPLE(LOG_ERR);

	if (syslog_enabled)
		syslog(LOG_ERR, "  libcrypto error stack:");
	if (fprintf_enabled)
		__fprintf(LOG_ERR, "  libcrypto error stack:");

	stack_size = 0;
	ERR_print_errors_cb(log_crypto_error, &stack_size);
	if (stack_size == 0) {
		if (syslog_enabled)
			syslog(LOG_ERR, "    <Empty>");
		if (fprintf_enabled)
			__fprintf(LOG_ERR, "    <Empty>\n");
	}

	return -EINVAL;
}

int
pr_enomem(void)
{
	if (syslog_enabled)
		syslog(LOG_ERR, "Out of memory.");
	if (fprintf_enabled)
		__fprintf(LOG_ERR, "Out of memory.\n");
	return -ENOMEM;
}

__dead void
pr_crit(const char *format, ...)
{
	PR_SIMPLE(LOG_CRIT);
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
		PR_SIMPLE(LOG_WARNING);
		return 0;
	case INAC_ERROR:
		PR_SIMPLE(LOG_ERR);
		return -EINVAL;
	}

	pr_crit("Unknown incidence action: %u", action);
}
