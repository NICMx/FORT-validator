#ifndef SRC_LOG_H_
#define SRC_LOG_H_

#include <stdbool.h>
#include <stdio.h>
#include <sys/queue.h>

#define CLR_DBG	"\x1B[36m"	/* Cyan */
#define CLR_CLT	"\x1B[34m"	/* Blue */
#define CLR_TRC	"\x1B[32m"	/* Green */
#define CRL_INF "\x1b[37m"	/* White */
#define CLR_WRN	"\x1B[33m"	/* Yellow */
#define CLR_ERR	"\x1B[31m"	/* Red */
#define CLR_CRT	"\x1B[35m"	/* Magenta */
#define CLR_PNC	"\x1B[35m"	/* Magenta */
#define CLR_RST	"\x1B[0m"

/*
 * According to BSD style, __dead is supposed to be defined in sys/cdefs.h,
 * but it doesn't exist in Linux.
 */
#ifndef __dead
#if __GNUC__
#define __dead __attribute__((noreturn))
#else
#define __dead /* Nothing */
#endif
#endif

#if __GNUC__
#define CHECK_FORMAT(str, args) __attribute__((format(printf, str, args)))
#else
#define CHECK_FORMAT(str, args) /* Nothing */
#endif

struct log_listener {
	char const *type;
	char const *level;
	char const *filename;	/* file only */
	bool print_times;	/* console and file only */
	bool color;		/* console and file only */
	int facility;		/* syslog only */

	TAILQ_ENTRY(log_listener) lh;
};

TAILQ_HEAD(log_listeners, log_listener);

void log_setup(void);			/* Enables pr_* functions */
int log_init(struct log_listeners *);	/* Loads configuration */
void log_teardown(void);

/*
 * DBG (Debug) = Dirty lazy (debuggerless) bug hunting prints.
 * These should be removed after the fix, and are always purged during releases.
 * They go straight to standard output, bypassing listeners (and their levels).
 *
 * CLT (Clutter) = Low-level "I'm doing this now."
 * TRC (Trace) = High-level "I'm doing this now."
 * TRCs contextualize errors; CLTs give detailed information once the dev
 * understands the context.
 * TRCs are permanent; CLTs need to be compiled in. This is because I've
 * extremely rarely found CLTs useful, even when debugging, and I got tired of
 * them.
 * In syslog, both are mapped to LOG_DEBUG.
 *
 * INF (Info) = Rare significant benign event.
 *
 * WRN (Warning) = Weirdness found, object not rejected, validation recovers.
 * Means "this doesn't look rational, but I'll humor you anyway."
 *
 * ERR (Error) = Error, object rejected, validation recovers.
 * Typical nonfatal expected error. A "checked exception," if you will.
 *
 * CRIT (Critical) = Apalling error, object rejected, validation recovers.
 * A somehow nonfatal programming error.
 * These include stack traces, and are not meant for reports.
 *
 * PNC (Panic) = Crippling error, validation dies.
 * This is what CRIT used to be; Fort dies on the spot. Also includes a stack
 * trace. Mapped to LOG_EMERG.
 * With the exception of ENOMEMs, PNCs should never happen in production.
 *
 * WRNs and ERRs are redirected to reports during validations.
 */

#ifdef PR_CLUTTER_ENABLED
#define pr_clutter_enabled() true
void pr_clutter(const char *, ...) CHECK_FORMAT(1, 2);
#else
#define pr_clutter_enabled() false
#define pr_clutter(...)
#endif

bool pr_trc_enabled(void);

void pr_trc(const char *, ...) CHECK_FORMAT(1, 2);
void pr_inf(const char *, ...) CHECK_FORMAT(1, 2);
int pr_wrn(const char *, ...) CHECK_FORMAT(1, 2);
int pr_err(const char *, ...) CHECK_FORMAT(1, 2);
/* Like pr_err(), but also prints libcrypto's error stack */
int pr_crypto_err(const char *, ...) CHECK_FORMAT(1, 2);
int pr_crit(const char *, ...) CHECK_FORMAT(1, 2);
__dead void pr_panic(const char *, ...) CHECK_FORMAT(1, 2);
__dead void enomem_panic(void); /* Out of memory */

#define PR_DBG(msg, ...) do {						\
		printf(CLR_DBG "%s:%d (%s()): " msg CLR_RST "\n",	\
		    __FILE__, __LINE__, __func__, ##__VA_ARGS__);	\
		fflush(stdout);						\
	} while (0)
#define PR_HELLO do {							\
		printf(CLR_DBG "%s:%d (%s())" CLR_RST "\n",		\
		    __FILE__, __LINE__, __func__);			\
		fflush(stdout);						\
	} while (0)

#endif /* SRC_LOG_H_ */
