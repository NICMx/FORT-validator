#define _DEFAULT_SOURCE 1

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
#include <unistd.h>

#include "config.h"
#include "report.h"
#include "types/fnstack.h"
#include "types/list.h"
#include "types/path.h"

struct log_listener {
	char const *type;
	uint8_t level;
	char const *filename;	/* file only */
	bool print_times;	/* console and file only */
	bool color;		/* console and file only */

	TAILQ_ENTRY(log_listener) lh;
};

struct level {
	int id;
	char const *tag;
	char const *name;
	char const *color;
	char const *rst;
	bool print_filenames;
};

#ifdef PR_CLUTTER_ENABLED
static struct level CLT = { LOG_DEBUG, "CLT", "clutter", CLR_CLT, CLR_RST, false };
#endif
static struct level TRC = { LOG_DEBUG, "TRC", "trace", CLR_TRC, CLR_RST, false };
static struct level INF = { LOG_INFO, "INF", "info", "", "", false };
static struct level WRN = { LOG_WARNING, "WRN", "warning", CLR_WRN, CLR_RST, false };
static struct level ERR = { LOG_ERR, "ERR", "error", CLR_ERR, CLR_RST, false };
static struct level CRT = { LOG_CRIT, "CRT", "critical", CLR_CRT, CLR_RST, false };
static struct level PNC = { LOG_EMERG, "PNC", "panic", CLR_PNC, CLR_RST, false };

/* Validation warning (reported, so logged on trace level, except yellow) */
static struct level TRC_WRN = { LOG_DEBUG, "TRW", NULL, CLR_WRN, CLR_RST, true };
/* Validation error (reported, so logged on trace level, except red) */
static struct level TRC_ERR = { LOG_DEBUG, "TRE", NULL, CLR_ERR, CLR_RST, true };

struct logger {
	void (*cb)(struct logger *, struct level *, char const *, va_list);

	struct level *lvl;
	FILE *stream;		/* file only */
	enum ts_type tst;	/* console and file only */
	bool color;		/* console and file only */
	bool free;

	pthread_mutex_t *lock;	/* console (except init) and file only */
	SLIST_ENTRY(logger) lh;
};

SLIST_HEAD(loggers, logger);

/* Constant after init */
static struct loggers listeners = SLIST_HEAD_INITIALIZER(listeners);
static bool trc_enabled;

static void
vcb(struct logger *lgr, struct level *lvl, char const *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	lgr->cb(lgr, lvl, fmt, vl);
	va_end(vl);
}

#ifdef BACKTRACE_ENABLED

#define STACK_SIZE 64

/*
 * Needs -rdynamic, otherwise function names don't show up.
 * Only non-static functions can be labeled.
 */
static void
__pr_stack_trace(struct logger *lgr, struct level *lvl,
    char const *title, size_t size, char **strings)
{
	size_t i;

	if (title != NULL)
		vcb(lgr, lvl, "%s", title);
	vcb(lgr, lvl, "Stack trace:");
	for (i = 0; i < size; i++)
		vcb(lgr, lvl, "  %s", strings[i]);
	vcb(lgr, lvl, "(End of stack trace)");
}

#endif /* BACKTRACE_ENABLED */

static void
init_mutex(struct logger *lgr)
{
	int error;

	lgr->lock = pmalloc(sizeof(pthread_mutex_t));

	error = pthread_mutex_init(lgr->lock, NULL);
	if (error) {
		pr_wrn("Cannot initialize logging mutex: %s. "
		    "Logs might overlap sometimes.", strerror(error));
		free(lgr->lock);
		lgr->lock = NULL;
	}
}

static void
print_timestamp(FILE *out, enum ts_type tst)
{
	char buf[21];
	time_t now;
	struct tm parts;

	switch (tst) {
	case TST_OFF:
		return;

	case TST_UTC:
		now = time(NULL);
		if (now == ((time_t) -1))
			return;
		if (gmtime_r(&now, &parts) == NULL)
			return;
		if (!strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &parts))
			return;
		break;

	case TST_LOCAL:
		now = time(NULL);
		if (now == ((time_t) -1))
			return;
		if (localtime_r(&now, &parts) == NULL)
			return;
		if (!strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &parts))
			return;
		break;
	}

	fprintf(out, "%s ", buf);
}

static void
print_filename(FILE *out)
{
	char const *filename;

	filename = fnstack_peek();
	if (filename)
		fprintf(out, "%s: ", filename);
}

static void
stream_print(FILE *out, struct logger *lgr, struct level *lvl,
    char const *fmt, va_list vl)
{
	if (lgr->lock)
		pthread_mutex_lock(lgr->lock);

	if (lgr->color)
		fprintf(out, "%s", lvl->color);
	print_timestamp(out, lgr->tst);
	fprintf(out, "%s: ", lvl->tag);
	if (lvl->print_filenames)
		print_filename(out);
	vfprintf(out, fmt, vl);
	fprintf(out, "%s\n", lgr->color ? lvl->rst : "");

	if (lgr->lock)
		pthread_mutex_unlock(lgr->lock);
}

static void
console_cb(struct logger *lgr, struct level *lvl, char const *fmt, va_list vl)
{
	FILE *stream;

	stream = (lvl->id <= LOG_ERR) ? stderr : stdout;
	stream_print(stream, lgr, lvl, fmt, vl);
	fflush(stream);
}

/*
static void
file_cb(struct logger *lgr, struct level *lvl, char const *fmt, va_list vl)
{
	stream_print(lgr->stream, lgr, lvl, fmt, vl);
}
*/

static void
syslog_cb(struct logger *lgr, struct level *lvl, char const *fmt, va_list vl)
{
	vsyslog(lvl->id | LOG_DAEMON, fmt, vl);
}

void
log_setup(void)
{
	static struct logger init_node = { 0 };

	init_node.cb = console_cb;
	init_node.lvl = &INF;

	SLIST_INSERT_HEAD(&listeners, &init_node, lh);
}

static int
id2level(int id, struct level **lvl)
{
	if (id == ERR.id)
		*lvl = &ERR;
	else if (id == WRN.id)
		*lvl = &WRN;
	else if (id == INF.id)
		*lvl = &INF;
	else if (id == TRC.id)
		*lvl = &TRC;
	else
		return pr_err("Unknown log level: %u", id);
	return 0;
}

static void
free_logger(struct logger *lgr)
{
	if (lgr->stream)
		fclose(lgr->stream);
	if (lgr->lock) {
		pthread_mutex_destroy(lgr->lock);
		free(lgr->lock);
	}
	if (lgr->free)
		free(lgr);
}

static void
clear_loggers(struct loggers *list)
{
	struct logger *lgr;

	while ((lgr = SLIST_FIRST(list)) != NULL) {
		SLIST_REMOVE_HEAD(list, lh);
		free_logger(lgr);
	}
}

int
log_init(void)
{
	static struct logger syslogger;
	static struct logger stdlogger;
	struct loggers newlist;
	int error;

	SLIST_INIT(&newlist);

	if (fortcfg.log.syslog.level.state == LLS_ENABLED) {
		openlog("fort", 0, LOG_DAEMON);

		syslogger.cb = syslog_cb;
		error = id2level(fortcfg.log.syslog.level.val, &syslogger.lvl);
		if (error)
			goto fail;
		syslogger.stream = NULL;
		syslogger.tst = TST_OFF;
		syslogger.color = false;
		syslogger.free = false;
		syslogger.lock = NULL;
		SLIST_INSERT_HEAD(&newlist, &syslogger, lh);

		if (syslogger.lvl == &TRC)
			trc_enabled = true;
	}

	if (fortcfg.log.console.level.state == LLS_ENABLED) {
 		stdlogger.cb = console_cb;
		error = id2level(fortcfg.log.console.level.val, &stdlogger.lvl);
		if (error)
			goto fail;
		stdlogger.stream = NULL;
		stdlogger.tst = fortcfg.log.console.timestamps;
		stdlogger.color = fortcfg.log.console.color;
		stdlogger.free = false;
		init_mutex(&stdlogger);
		SLIST_INSERT_HEAD(&newlist, &stdlogger, lh);

		if (stdlogger.lvl == &TRC)
			trc_enabled = true;
	}

	clear_loggers(&listeners);
	listeners = newlist;
	return 0;

fail:	clear_loggers(&newlist);
	return error;
}

/* Removes the standard stream logging handlers */
void
log_silence_std(void)
{
	struct logger *lgr, *tmp;

	SLIST_FOREACH_SAFE(lgr, &listeners, lh, tmp) {
		if (lgr->cb == console_cb) {
			SLIST_REMOVE(&listeners, lgr, logger, lh);
			free_logger(lgr);
		}
	}
}

void
log_teardown(void)
{
	struct logger *lgr;
	bool has_syslog = false;

	while ((lgr = SLIST_FIRST(&listeners)) != NULL) {
		if (lgr->cb == syslog_cb)
			has_syslog = true;
		SLIST_REMOVE_HEAD(&listeners, lh);
		free_logger(lgr);
	}

	if (has_syslog)
		closelog();
}

#ifdef PR_CLUTTER_ENABLED

void
pr_clutter(const char *fmt, ...)
{
	struct logger *lgr;
	va_list args;

	SLIST_FOREACH(lgr, &listeners, lh) {
		if (LOG_DEBUG <= lgr->lvl->id) {
			va_start(args, fmt);
			lgr->cb(lgr, &CLT, fmt, args);
			va_end(args);
		}
	}
}

#endif

bool
pr_trc_enabled(void)
{
	return trc_enabled;
}

void
pr_trc(const char *fmt, ...)
{
	struct logger *lgr;
	va_list args;

	SLIST_FOREACH(lgr, &listeners, lh) {
		if (LOG_DEBUG <= lgr->lvl->id) {
			va_start(args, fmt);
			lgr->cb(lgr, &TRC, fmt, args);
			va_end(args);
		}
	}
}

void
pr_inf(const char *fmt, ...)
{
	struct logger *lgr;
	va_list args;

	SLIST_FOREACH(lgr, &listeners, lh) {
		if (LOG_INFO <= lgr->lvl->id) {
			va_start(args, fmt);
			lgr->cb(lgr, &INF, fmt, args);
			va_end(args);
		}
	}
}

int
pr_wrn(const char *fmt, ...)
{
	struct level *lvl = &WRN;
	struct logger *lgr;
	va_list args;

	if (report_enabled()) {
		va_start(args, fmt);
		report(lvl->tag, fmt, args);
		va_end(args);
		lvl = &TRC_WRN;
	}

	SLIST_FOREACH(lgr, &listeners, lh) {
		if (lvl->id <= lgr->lvl->id) {
			va_start(args, fmt);
			lgr->cb(lgr, lvl, fmt, args);
			va_end(args);
		}
	}

	return 0;
}

int
pr_err(const char *fmt, ...)
{
	struct level *lvl = &ERR;
	struct logger *lgr;
	va_list args;

	if (report_enabled()) {
		va_start(args, fmt);
		report(lvl->tag, fmt, args);
		va_end(args);
		lvl = &TRC_ERR;
	}

	SLIST_FOREACH(lgr, &listeners, lh) {
		if (lvl->id <= lgr->lvl->id) {
			va_start(args, fmt);
			lgr->cb(lgr, lvl, fmt, args);
			va_end(args);
		}
	}

	return EINVAL;
}

static int
log_crypto_error(const char *str, size_t len, void *_stack_size)
{
	unsigned int *stack_size = _stack_size;
	pr_err("-> %s", str);
	(*stack_size)++;
	return 1;
}

/**
 * This is like pr_err(), except meant to log an error made during a libcrypto
 * routine.
 *
 * This differs from usual printf-like functions:
 *
 * - It returns EINVAL, not bytes written.
 * - It prints a newline.
 * - Also prints the cryptolib's error message stack.
 */
int
pr_crypto_err(const char *fmt, ...)
{
	struct level *lvl = &ERR;
	struct logger *lgr;
	va_list args;
	unsigned int stack_size;

	if (report_enabled()) {
		va_start(args, fmt);
		report(lvl->tag, fmt, args);
		va_end(args);
		lvl = &TRC_ERR;
	}

	SLIST_FOREACH(lgr, &listeners, lh) {
		if (lvl->id <= lgr->lvl->id) {
			va_start(args, fmt);
			lgr->cb(lgr, lvl, fmt, args);
			va_end(args);
		}
	}

	pr_err("libcrypto error stack:");
	stack_size = 0;
	ERR_print_errors_cb(log_crypto_error, &stack_size);
	if (stack_size == 0)
		pr_err("   <Empty>");
	else
		pr_err("End of libcrypto stack.");

	return EINVAL;
}

int
pr_crit(const char *fmt, ...)
{
	struct logger *lgr;
	va_list args;

#ifdef BACKTRACE_ENABLED
	void *array[STACK_SIZE];
	size_t size;
	char **strings;

	size = backtrace(array, STACK_SIZE);
	strings = backtrace_symbols(array, size);
#endif

	SLIST_FOREACH(lgr, &listeners, lh) {
		if (CRT.id <= lgr->lvl->id) {
			va_start(args, fmt);
			lgr->cb(lgr, &CRT, fmt, args);
			va_end(args);

#ifdef BACKTRACE_ENABLED
			__pr_stack_trace(lgr, &CRT, NULL, size, strings);
#endif
		}
	}

#ifdef BACKTRACE_ENABLED
	free(strings);
#endif

	return EINVAL;
}

__dead void
pr_panic(const char *fmt, ...)
{
	struct logger *lgr;
	va_list args;

#ifdef BACKTRACE_ENABLED
	void *array[STACK_SIZE];
	size_t size;
	char **strings;

	size = backtrace(array, STACK_SIZE);
	strings = backtrace_symbols(array, size);
#endif

	SLIST_FOREACH(lgr, &listeners, lh) {
		if (LOG_CRIT <= lgr->lvl->id) {
			va_start(args, fmt);
			lgr->cb(lgr, &PNC, fmt, args);
			va_end(args);

#ifdef BACKTRACE_ENABLED
			__pr_stack_trace(lgr, &PNC, NULL, size, strings);
#endif
		}
	}

#ifdef BACKTRACE_ENABLED
	free(strings);
#endif

	exit(-1);
}

__dead void
enomem_panic(void)
{
	struct logger *lgr;

	SLIST_FOREACH(lgr, &listeners, lh)
		if (LOG_CRIT <= lgr->lvl->id)
			vcb(lgr, &CRT, "Out of memory");

	exit(ENOMEM);
}
