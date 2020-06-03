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

/* LOG_PERROR is not portable, apparently, so I implemented it myself */
static bool op_fprintf_enabled;
static bool op_syslog_enabled;
static bool val_fprintf_enabled;
static bool val_syslog_enabled;

static bool op_global_log_enabled;
static bool val_global_log_enabled;

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
	op_fprintf_enabled = true;
	op_syslog_enabled = true;
	val_fprintf_enabled = true;
	val_syslog_enabled = true;

	op_global_log_enabled = true;
	val_global_log_enabled = true;
}

static void
log_disable_op_std(void)
{
	op_fprintf_enabled = false;
}

static void
log_disable_val_std(void)
{
	val_fprintf_enabled = false;
}

static void
log_disable_syslog(void)
{
	if (op_syslog_enabled || val_syslog_enabled) {
		closelog();
		op_syslog_enabled = false;
		val_syslog_enabled = false;
	}
}

void
log_start(void)
{
	val_global_log_enabled = config_get_val_log_enabled();
	op_global_log_enabled = config_get_op_log_enabled();

	if (val_global_log_enabled) {
		switch (config_get_val_log_output()) {
		case SYSLOG:
			pr_op_info("Syslog log output configured; disabling validation logging on standard streams.");
			pr_op_info("(Validation Logs will be sent to syslog only.)");
			log_disable_val_std();
			break;
		case CONSOLE:
			pr_op_info("Console log output configured; disabling validation logging on syslog.");
			pr_op_info("(Validation Logs will be sent to the standard streams only.)");
			val_syslog_enabled = false;
			break;
		}
	} else {
		pr_op_info("Disabling validation logging on syslog.");
		pr_op_info("Disabling validation logging on standard streams.");
		log_disable_val_std();
		val_syslog_enabled = false;
	}



	if (op_global_log_enabled) {
		switch (config_get_op_log_output()) {
		case SYSLOG:
			pr_op_info("Syslog log output configured; disabling operation logging on standard streams.");
			pr_op_info("(Operation Logs will be sent to syslog only.)");
			log_disable_op_std();
			break;
		case CONSOLE:
			pr_op_info("Console log output configured; disabling operation logging on syslog.");
			pr_op_info("(Operation Logs will be sent to the standard streams only.)");
			if (!val_syslog_enabled)
				log_disable_syslog();
			else
				op_syslog_enabled = false;
			break;
		}
	} else {
		pr_op_info("Disabling operation logging on syslog.");
		pr_op_info("Disabling operation logging on standard streams.");
		log_disable_op_std();
		if (!val_syslog_enabled)
			log_disable_syslog();
		else
			op_syslog_enabled = false;
	}


}

void
log_teardown(void)
{
	log_disable_op_std();
	log_disable_val_std();
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
__fprintf(int level, char const *prefix, bool color_output,
    char const *format, ...)
{
	struct level const *lvl;
	va_list args;
	char time_buff[20];
	time_t now;
	struct tm stm_buff;

	lvl = level2struct(level);

	if (color_output)
		fprintf(lvl->stream, "%s", lvl->color);

	now = time(0);
	if (now != ((time_t) -1)) {
		localtime_r(&now, &stm_buff);
		strftime(time_buff, sizeof(time_buff), "%b %e %T", &stm_buff);
		fprintf(lvl->stream, "%s ", time_buff);
	}

	fprintf(lvl->stream, "%s", lvl->label);
	if (prefix)
		fprintf(lvl->stream, " [%s]", prefix);
	fprintf(lvl->stream, ": ");

	va_start(args, format);
	vfprintf(lvl->stream, format, args);
	va_end(args);

	if (color_output)
		fprintf(lvl->stream, COLOR_RESET);

	fprintf(lvl->stream, "\n");
	/* Force flush */
	if (lvl->stream == stdout)
		fflush(lvl->stream);
}

#define MSG_LEN 512

static void
pr_syslog(int level, char const *prefix, const char *format, int facility,
    va_list args)
{
	char const *file_name;
	struct level const *lvl;
	char msg[MSG_LEN];

	file_name = fnstack_peek();
	lvl = level2struct(level);

	/* Can't use vsyslog(); it's not portable. */
	vsnprintf(msg, MSG_LEN, format, args);
	if (file_name != NULL) {
		if (prefix != NULL)
			syslog(level | facility, "%s [%s]: %s: %s", lvl->label,
			    prefix, file_name, msg);
		else
			syslog(level | facility, "%s: %s: %s", lvl->label,
			    file_name, msg);
	} else {
		if (prefix != NULL)
			syslog(level | facility, "%s [%s]: %s", lvl->label,
			    prefix, msg);
		else
			syslog(level | facility, "%s: %s", lvl->label, msg);
	}
}

static void
pr_stream(int level, char const *prefix, const char *format, bool color_output,
    va_list args)
{
	char const *file_name;
	char time_buff[20];
	struct level const *lvl;
	time_t now;
	struct tm stm_buff;

	file_name = fnstack_peek();
	lvl = level2struct(level);

	if (color_output)
		fprintf(lvl->stream, "%s", lvl->color);

	now = time(0);
	if (now != ((time_t) -1)) {
		localtime_r(&now, &stm_buff);
		strftime(time_buff, sizeof(time_buff), "%b %e %T", &stm_buff);
		fprintf(lvl->stream, "%s ", time_buff);
	}

	fprintf(lvl->stream, "%s", lvl->label);
	if (prefix)
		fprintf(lvl->stream, " [%s]", prefix);
	fprintf(lvl->stream, ": ");

	if (file_name != NULL)
		fprintf(lvl->stream, "%s: ", file_name);
	vfprintf(lvl->stream, format, args);

	if (color_output)
		fprintf(lvl->stream, "%s", COLOR_RESET);

	fprintf(lvl->stream, "\n");
	/* Force flush */
	if (lvl->stream == stdout)
		fflush(lvl->stream);
}

#define PR_OP_SIMPLE(level)						\
	do {								\
		va_list args;						\
		char const *prefix = config_get_op_log_prefix();	\
		bool color = config_get_op_log_color_output();		\
		int facility = config_get_op_log_facility();		\
									\
		if (!op_global_log_enabled)				\
			break;						\
									\
		if (level > config_get_op_log_level())			\
			break;						\
									\
		if (op_syslog_enabled) {				\
			va_start(args, format);				\
			pr_syslog(level, prefix, format, facility,	\
			    args);					\
			va_end(args);					\
		}							\
									\
		if (op_fprintf_enabled) {				\
			va_start(args, format);				\
			pr_stream(level, prefix, format, color, args);	\
			va_end(args);					\
		}							\
	} while (0)


#define PR_VAL_SIMPLE(level)						\
	do {								\
		va_list args;						\
		char const *prefix = config_get_val_log_prefix();	\
		bool color = config_get_val_log_color_output();		\
		int facility = config_get_val_log_facility();		\
									\
		if (!val_global_log_enabled)				\
			break;						\
									\
		if (level > config_get_val_log_level())			\
			break;						\
									\
		if (val_syslog_enabled) {				\
			va_start(args, format);				\
			pr_syslog(level, prefix, format, facility,	\
			    args);					\
			va_end(args);					\
		}							\
									\
		if (val_fprintf_enabled) {				\
			va_start(args, format);				\
			pr_stream(level, prefix, format, color, args);	\
			va_end(args);					\
		}							\
	} while (0)

bool
log_val_debug_enabled(void)
{
	return config_get_val_log_level() >= LOG_DEBUG;
}

bool
log_op_debug_enabled(void)
{
	return config_get_op_log_level() >= LOG_DEBUG;
}

bool
log_op_info_enabled(void)
{
	return config_get_op_log_level() >= LOG_INFO;
}

void
pr_op_debug(const char *format, ...)
{
	PR_OP_SIMPLE(LOG_DEBUG);
}

void
pr_op_info(const char *format, ...)
{
	PR_OP_SIMPLE(LOG_INFO);
}

/**
 * Always returs 0. (So you can interrupt whatever you're doing without failing
 * validation.)
 */
int
pr_op_warn(const char *format, ...)
{
	PR_OP_SIMPLE(LOG_WARNING);
	return 0;
}

/**
 * Always returs -EINVAL.
 */
int
pr_op_err(const char *format, ...)
{
	PR_OP_SIMPLE(LOG_ERR);
	return -EINVAL;
}

void
pr_val_debug(const char *format, ...)
{
	PR_VAL_SIMPLE(LOG_DEBUG);
}

void
pr_val_info(const char *format, ...)
{
	PR_VAL_SIMPLE(LOG_INFO);
}

/**
 * Always returs 0. (So you can interrupt whatever you're doing without failing
 * validation.)
 */
int
pr_val_warn(const char *format, ...)
{
	PR_VAL_SIMPLE(LOG_WARNING);
	return 0;
}

/**
 * Always returs -EINVAL.
 */
int
pr_val_err(const char *format, ...)
{
	PR_VAL_SIMPLE(LOG_ERR);
	return -EINVAL;
}

static void
pr_simple_syslog(int level, int facility, char const *prefix, const char *msg)
{
	struct level const *lvl;

	lvl = level2struct(LOG_ERR);
	if (prefix != NULL)
		syslog(LOG_ERR | facility, "%s [%s]: - %s", lvl->label, prefix,
		    msg);
	else
		syslog(LOG_ERR | facility, "%s: - %s", lvl->label, msg);
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
static int
pr_errno(int error, bool syslog_enabled, bool fprintf_enabled, int facility,
    bool color, char const *prefix)
{
	if (!error)
		return -EINVAL;

	if (syslog_enabled)
		pr_simple_syslog(LOG_ERR, facility, prefix, strerror(error));

	if (fprintf_enabled)
		__fprintf(LOG_ERR, prefix, color, "  - %s", strerror(error));

	return error;
}


int
pr_op_errno(int error, const char *format, ...)
{
	PR_OP_SIMPLE(LOG_ERR);

	return pr_errno(error, op_syslog_enabled,
	    op_fprintf_enabled, config_get_op_log_facility(),
	    config_get_op_log_color_output(),
	    config_get_op_log_prefix());
}

int
pr_val_errno(int error, const char *format, ...)
{
	PR_VAL_SIMPLE(LOG_ERR);

	return pr_errno(error, val_syslog_enabled,
	    val_fprintf_enabled, config_get_val_log_facility(),
	    config_get_val_log_color_output(),
	    config_get_val_log_prefix());
}

static int
log_op_crypto_error(const char *str, size_t len, void *arg)
{
	if (op_syslog_enabled)
		pr_simple_syslog(LOG_ERR, config_get_op_log_facility(),
		    config_get_op_log_prefix(), str);
	if (op_fprintf_enabled)
		__fprintf(LOG_ERR, config_get_op_log_prefix(),
		    config_get_op_log_color_output(),
		    "  - %s", str);
	return 1;
}

static int
log_val_crypto_error(const char *str, size_t len, void *arg)
{
	if (val_syslog_enabled)
		pr_simple_syslog(LOG_ERR, config_get_val_log_facility(),
		    config_get_val_log_prefix(), str);
	if (val_fprintf_enabled)
		__fprintf(LOG_ERR, config_get_val_log_prefix(),
		    config_get_val_log_color_output(),
		    "  - %s", str);
	return 1;
}

static int
crypto_err(int (*cb) (const char *str, size_t len, void *u),
    bool fprintf_enabled, bool syslog_enabled, bool color_output, int facility,
    const char *prefix)
{
	unsigned int stack_size;

	if (syslog_enabled)
		pr_simple_syslog(LOG_ERR, facility, prefix,
		    " libcrypto error stack:");
	if (fprintf_enabled)
		__fprintf(LOG_ERR, prefix, color_output,
		    "  libcrypto error stack:");

	stack_size = 0;
	ERR_print_errors_cb(cb, &stack_size);
	if (stack_size == 0) {
		if (syslog_enabled)
			pr_simple_syslog(LOG_ERR, facility, prefix,
			    "   <Empty");
		if (fprintf_enabled)
			__fprintf(LOG_ERR, prefix, color_output,
			    "    <Empty>\n");
	}

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
	PR_OP_SIMPLE(LOG_ERR);

	return crypto_err(log_op_crypto_error, op_fprintf_enabled,
	    op_syslog_enabled, config_get_op_log_color_output(),
	    config_get_op_log_facility(), config_get_op_log_prefix());
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
	PR_VAL_SIMPLE(LOG_ERR);

	return crypto_err(log_val_crypto_error, val_fprintf_enabled,
	    val_syslog_enabled, config_get_val_log_color_output(),
	    config_get_val_log_facility(), config_get_val_log_prefix());
}

/**
 * This is an operation log
 **/
int
pr_enomem(void)
{
	if (op_syslog_enabled)
		pr_simple_syslog(LOG_ERR, config_get_op_log_facility(),
		    config_get_op_log_prefix(), "Out of memory.");
	if (op_fprintf_enabled)
		__fprintf(LOG_ERR, config_get_op_log_prefix(),
		    config_get_op_log_color_output(),
		    "Out of memory.\n");
	return -ENOMEM;
}

/**
 * This is an operation log
 **/
__dead void
pr_crit(const char *format, ...)
{
	PR_OP_SIMPLE(LOG_CRIT);
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
		PR_VAL_SIMPLE(LOG_WARNING);
		return 0;
	case INAC_ERROR:
		PR_VAL_SIMPLE(LOG_ERR);
		return -EINVAL;
	}

	pr_crit("Unknown incidence action: %u", action);
}
