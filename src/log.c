#include "log.h"

#include <errno.h>
#ifdef BACKTRACE_ENABLED
#include <execinfo.h>
#endif
#include <openssl/err.h>
#include <pthread.h>
#include <stdarg.h>
#include <syslog.h>
#include <time.h>

#include "config.h"
#include "thread_var.h"
#include "types/path.h"

struct level {
	char const *label;
	char const *color;
	FILE *stream;
};

static struct level DBG = { "DBG", PR_COLOR_DBG };
static struct level INF = { "INF", PR_COLOR_INF };
static struct level WRN = { "WRN", PR_COLOR_WRN };
static struct level ERR = { "ERR", PR_COLOR_ERR };
static struct level CRT = { "CRT", PR_COLOR_CRT };
static struct level UNK = { "UNK", "" };

struct log_config {
	bool fprintf_enabled; /* Print on the standard streams? */
	bool syslog_enabled; /* Print on syslog? */

	uint8_t level;
	char const *tag;
	bool color;
	int facility;
	bool rm_filepath;
};

/* Configuration for the operation logs. */
static struct log_config op_config;
/* Configuration for the validation logs. */
static struct log_config val_config;

/*
 * fprintf and syslog are rarely enabled at the same time, so I reused the
 * mutex.
 *
 * "log" + "lock" = "logck"
 */
static pthread_mutex_t logck;

/**
 * Important: -rdynamic needs to be enabled, otherwise this does not print
 * function names. See LDFLAGS_DEBUG in Makefile.am.
 * Also: Only non-static functions will be labeled.
 *
 * The first printed entry is probably not meaningful. (But I'm printing
 * everything anyway due to paranoia.)
 *
 * @title is allowed to be NULL. If you need locking, do it outside. (And be
 * aware that pthread_mutex_lock() can return error codes, which shouldn't
 * prevent critical stack traces from printing.)
 */
static void
print_stack_trace(char const *title)
{
#ifdef BACKTRACE_ENABLED
#define STACK_SIZE 64

	void *array[STACK_SIZE];
	size_t size;
	char **strings;
	size_t i;
	int fp;

	size = backtrace(array, STACK_SIZE);
	strings = backtrace_symbols(array, size);

	if (op_config.fprintf_enabled) {
		if (title != NULL)
			fprintf(ERR.stream, "%s\n", title);
		fprintf(ERR.stream, "Stack trace:\n");
		for (i = 0; i < size; i++)
			fprintf(ERR.stream, "  %s\n", strings[i]);
		fprintf(ERR.stream, "(End of stack trace)\n");
	}

	if (op_config.syslog_enabled) {
		fp = LOG_ERR | op_config.facility;
		if (title != NULL)
			syslog(fp, "%s", title);
		syslog(fp, "Stack trace:");
		for (i = 0; i < size; i++)
			syslog(fp, "  %s", strings[i]);
		syslog(fp, "(End of stack trace)");
	}

	free(strings);
#endif /* BACKTRACE_ENABLED */
}

static void init_config(struct log_config *cfg)
{
	cfg->fprintf_enabled = true;
	cfg->syslog_enabled = true;
	cfg->level = LOG_DEBUG;
	cfg->tag = NULL;
	cfg->color = false;
	cfg->facility = LOG_DAEMON;
}

int
log_setup(void)
{
	/*
	 * Remember not to use any actual logging functions until logging has
	 * been properly initialized.
	 */

	int error;

	DBG.stream = stdout;
	INF.stream = stdout;
	WRN.stream = stderr;
	ERR.stream = stderr;
	CRT.stream = stderr;
	UNK.stream = stdout;

	init_config(&op_config);
	init_config(&val_config);

	error = pthread_mutex_init(&logck, NULL);
	if (error) {
		fprintf(ERR.stream,
		    "pthread_mutex_init() failure: %s\n",
		    strerror(error));
		syslog(LOG_ERR | op_config.facility,
		    "pthread_mutex_init() failure: %s",
		    strerror(error));
		return error;
	}

	return 0;
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
			val_config.fprintf_enabled = false;
			break;
		case CONSOLE:
			val_config.syslog_enabled = false;
			break;
		}
	} else {
		val_config.fprintf_enabled = false;
		val_config.syslog_enabled = false;
	}

	if (config_get_op_log_enabled()) {
		switch (config_get_op_log_output()) {
		case SYSLOG:
			op_config.fprintf_enabled = false;
			break;
		case CONSOLE:
			if (val_config.syslog_enabled)
				op_config.syslog_enabled = false;
			else
				log_disable_syslog();
			break;
		}
	} else {
		op_config.fprintf_enabled = false;
		if (val_config.syslog_enabled)
			op_config.syslog_enabled = false;
		else
			log_disable_syslog();
	}

	op_config.level = config_get_op_log_level();
	op_config.tag = config_get_op_log_tag();
	op_config.color = config_get_op_log_color_output();
	op_config.facility = config_get_op_log_facility();
	op_config.rm_filepath = config_get_op_log_file_format() == FNF_NAME;
	val_config.level = config_get_val_log_level();
	val_config.tag = config_get_val_log_tag();
	val_config.color = config_get_val_log_color_output();
	val_config.facility = config_get_val_log_facility();
	val_config.rm_filepath = config_get_val_log_file_format() == FNF_NAME;
}

void
log_teardown(void)
{
	log_disable_syslog();
	pthread_mutex_destroy(&logck);
}

bool
pr_val_enabled(unsigned int level)
{
	return val_config.level >= level;
}

bool
pr_op_enabled(unsigned int level)
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
lock_mutex(void)
{
	int error;

	error = pthread_mutex_lock(&logck);
	if (error) {
		/*
		 * Despite being supposed to be impossible, failing to lock the
		 * mutex is not fatal; it just means we might log some mixed
		 * messages, which is better than dying.
		 *
		 * Furthermore, this might have been called while logging
		 * another critical. We must absolutely not get in the way of
		 * that critical's print.
		 */
		print_stack_trace(strerror(error));
	}
}

static void
unlock_mutex(void)
{
	int error;

	error = pthread_mutex_unlock(&logck);
	if (error)
		print_stack_trace(strerror(error)); /* Same as above. */
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

	lock_mutex();

	if (cfg->color)
		fprintf(lvl->stream, "%s", lvl->color);

	now = time(NULL);
	if (now != ((time_t) -1)) {
		// XXX not catching any errors
		localtime_r(&now, &stm_buff);
		strftime(time_buff, sizeof(time_buff), "%b %e %T", &stm_buff);
		fprintf(lvl->stream, "%s ", time_buff);
	}

	fprintf(lvl->stream, "%s", lvl->label);
	if (cfg->tag)
		fprintf(lvl->stream, " [%s]", cfg->tag);
	fprintf(lvl->stream, ": ");

	file_name = fnstack_peek();
	if (file_name != NULL) {
		if (cfg->rm_filepath)
			file_name = path_filename(file_name);
		fprintf(lvl->stream, "%s: ", file_name);
	}

	vfprintf(lvl->stream, format, args);

	if (cfg->color)
		fprintf(lvl->stream, PR_COLOR_RST);
	fprintf(lvl->stream, "\n");

	/* Force flush */
	if (lvl->stream == stdout)
		fflush(lvl->stream);

	unlock_mutex();
}

/*
 * TODO (fine) Optimize. Notice the buffer is static, which seems to be the
 * reason why it's (probably ill-advisedly) mutexing.
 */
#define MSG_LEN 512

static void
__syslog(int level, struct log_config *cfg, const char *format, va_list args)
{
	static char msg[MSG_LEN];
	char const *file;
	int res;

	level |= cfg->facility;
	file = fnstack_peek();
	if (file && cfg->rm_filepath)
		file = path_filename(file);

	lock_mutex();

	/* Can't use vsyslog(); it's not portable. */
	res = vsnprintf(msg, MSG_LEN, format, args);
	if (res < 0)
		goto end;
	if (res >= MSG_LEN)
		msg[MSG_LEN - 1] = '\0';

	if (file != NULL) {
		if (cfg->tag != NULL)
			syslog(level, "[%s] %s: %s", cfg->tag, file, msg);
		else
			syslog(level, "%s: %s", file, msg);
	} else {
		if (cfg->tag != NULL)
			syslog(level, "[%s] %s", cfg->tag, msg);
		else
			syslog(level, "%s", msg);
	}

end:	unlock_mutex();
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
pr_op_err(const char *format, ...)
{
	PR_SIMPLE(LOG_ERR, op_config);
	return EINVAL;
}

int
pr_op_err_st(const char *format, ...)
{
	PR_SIMPLE(LOG_ERR, op_config);
	lock_mutex();
	print_stack_trace(NULL);
	unlock_mutex();
	return EINVAL;
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
pr_val_err(const char *format, ...)
{
	PR_SIMPLE(LOG_ERR, val_config);
	return EINVAL;
}

struct crypto_cb_arg {
	unsigned int stack_size;
	int (*error_fn)(const char *, ...);
};

static int
log_crypto_error(const char *str, size_t len, void *_arg)
{
	struct crypto_cb_arg *arg = _arg;
	arg->error_fn("-> %s", str);
	arg->stack_size++;
	return 1;
}

static int
crypto_err(struct log_config *cfg, int (*error_fn)(const char *, ...))
{
	struct crypto_cb_arg arg;

	error_fn("libcrypto error stack:");

	arg.stack_size = 0;
	arg.error_fn = error_fn;
	ERR_print_errors_cb(log_crypto_error, &arg);
	if (arg.stack_size == 0)
		error_fn("   <Empty>");
	else
		error_fn("End of libcrypto stack.");

	return EINVAL;
}

/**
 * This is like pr_err() and pr_errno(), except meant to log an error made
 * during a libcrypto routine.
 *
 * This differs from usual printf-like functions:
 *
 * - It returns EINVAL, not bytes written.
 * - It prints a newline.
 * - Also prints the cryptolib's error message stack.
 *
 * Always appends a newline at the end.
 */
int
op_crypto_err(const char *format, ...)
{
	PR_SIMPLE(LOG_ERR, op_config);
	return crypto_err(&op_config, pr_op_err);
}

/**
 * This is like pr_err() and pr_errno(), except meant to log an error made
 * during a libcrypto routine.
 *
 * This differs from usual printf-like functions:
 *
 * - It returns EINVAL, not bytes written.
 * - It prints a newline.
 * - Also prints the cryptolib's error message stack.
 *
 * Always appends a newline at the end.
 */
int
val_crypto_err(const char *format, ...)
{
	PR_SIMPLE(LOG_ERR, val_config);
	return crypto_err(&val_config, pr_val_err);
}

__dead void
enomem_panic(void)
{
	static char const *ENOMEM_MSG = "Out of memory.\n";
	ssize_t garbage;

	/*
	 * I'm not using PR_SIMPLE and friends, because those allocate.
	 * We want to minimize allocations after a memory allocation failure.
	 */

	if (LOG_ERR > op_config.level)
		goto done;

	if (op_config.fprintf_enabled) {
		lock_mutex();
		/*
		 * write() is AS-Safe, which implies it doesn't allocate,
		 * unlike printf().
		 *
		 * "garbage" prevents write()'s warn_unused_result (compiler
		 * warning).
		 */
		garbage = write(STDERR_FILENO, ENOMEM_MSG, strlen(ENOMEM_MSG));
		unlock_mutex();
		/* Prevents "set but not used" warning. */
		garbage += garbage;
	}

	if (op_config.syslog_enabled) {
		lock_mutex();
		/* This allocates, but I don't think I have more options. */
		syslog(LOG_ERR | op_config.facility, "Out of memory.");
		unlock_mutex();
	}

done:	exit(ENOMEM);
}

__dead void
pr_crit(const char *format, ...)
{
	PR_SIMPLE(LOG_ERR, op_config);
	print_stack_trace(NULL);
	exit(-1);
}
