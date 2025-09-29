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
#include "thread_var.h"
#include "types/path.h"

struct level {
	int id;
	char const *tag;
	char const *name;
	char const *color;
	char const *rst;
};

#ifdef PR_CLUTTER_ENABLED
static struct level CLT = { LOG_DEBUG, "CLT", "clutter", CLR_CLT, CLR_RST };
#endif
static struct level TRC = { LOG_DEBUG, "TRC", "trace", CLR_TRC, CLR_RST };
static struct level INF = { LOG_INFO, "INF", "info", "", "" };
static struct level WRN = { LOG_WARNING, "WRN", "warning", CLR_WRN, CLR_RST };
static struct level ERR = { LOG_ERR, "ERR", "error", CLR_ERR, CLR_RST };
static struct level CRT = { LOG_CRIT, "CRT", "critical", CLR_CRT, CLR_RST };
static struct level PNC = { LOG_EMERG, "PNC", "panic", CLR_PNC, CLR_RST };

struct logger {
	void (*cb)(struct logger *, struct level *, char const *, va_list);

	struct level *lvl;
	FILE *stream;		/* file only */
	bool print_times;	/* console and file only */
	bool color;		/* console and file only */
	int facility;		/* syslog only */
	bool free;

	pthread_mutex_t *lock;	/* console (except init) and file only */
	SLIST_ENTRY(logger) lh;
};

SLIST_HEAD(loggers, logger);

/* Constant after init */
static struct loggers listeners = SLIST_HEAD_INITIALIZER(listeners);

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
get_time(char *buf /* Must length 16 */)
{
	time_t now;
	struct tm components;

	now = time(NULL);
	if (now == ((time_t) -1))
		return;
	if (localtime_r(&now, &components) == NULL)
		return;
	if (strftime(buf, sizeof(buf), "%m-%d %H:%M:%S ", &components) == 0)
		buf[0] = 0;
}

static void
stream_print(FILE *out, struct logger *lgr, struct level *lvl,
    char const *fmt, va_list vl)
{
	char time[16];

	time[0] = 0;
	if (lgr->print_times)
		get_time(time);

	if (lgr->lock)
		pthread_mutex_lock(lgr->lock);

	fprintf(out, "%s%s%s: ", lgr->color ? lvl->color : "", time, lvl->tag);
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

static void
file_cb(struct logger *lgr, struct level *lvl, char const *fmt, va_list vl)
{
	stream_print(lgr->stream, lgr, lvl, fmt, vl);
}

static void
syslog_cb(struct logger *lgr, struct level *lvl, char const *fmt, va_list vl)
{
	vsyslog(lvl->id | lgr->facility, fmt, vl);
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
add_listener(struct loggers *list, struct log_listener *new)
{
	struct logger *node;

	node = pzalloc(sizeof(struct logger));
	node->free = true;

	if (strcmp(new->level, ERR.name) == 0)
		node->lvl = &ERR;
	else if (strcmp(new->level, WRN.name) == 0)
		node->lvl = &WRN;
	else if (strcmp(new->level, INF.name) == 0)
		node->lvl = &INF;
	else if (strcmp(new->level, TRC.name) == 0)
		node->lvl = &TRC;
	else {
		free(node);
		return pr_err("Unknown log level: %s", new->level);
	}

	if (strcmp(new->type, "console") == 0) {
		node->cb = console_cb;
		node->print_times = new->print_times;
		node->color = new->color;
		init_mutex(node);
	} else if (strcmp(new->type, "file") == 0) {
		node->cb = file_cb;
		node->stream = fopen(new->filename, "a");
		node->print_times = new->print_times;
		node->color = new->color;
		init_mutex(node);
	} else if (strcmp(new->type, "syslog") == 0) {
		node->cb = syslog_cb;
		node->facility = new->facility;
	} else {
		free(node);
		return pr_err("Unknown log type: %s", new->type);
	}

	SLIST_INSERT_HEAD(list, node, lh);
	return 0;
}

static void
clear_loggers(struct loggers *list)
{
	struct logger *lgr;

	while ((lgr = SLIST_FIRST(list)) != NULL) {
		if (lgr->stream)
			fclose(lgr->stream);
		if (lgr->lock) {
			pthread_mutex_destroy(lgr->lock);
			free(lgr->lock);
		}

		SLIST_REMOVE_HEAD(list, lh);
		if (lgr->free)
			free(lgr);
	}
}

int
log_init(struct log_listeners *descriptors)
{
	struct loggers newlist;
	struct log_listener *descriptor;
	int error;

	SLIST_INIT(&newlist);
	TAILQ_FOREACH(descriptor, descriptors, lh) {
		error = add_listener(&newlist, descriptor);
		if (error) {
			clear_loggers(&newlist);
			return error;
		}
	}

	clear_loggers(&listeners);
	listeners = newlist;
	return 0;
}

void
log_teardown(void)
{
	clear_loggers(&listeners);
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
		lvl = &TRC;
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
		lvl = &TRC;
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
		lvl = &TRC;
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
