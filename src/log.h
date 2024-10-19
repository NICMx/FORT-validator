#ifndef SRC_LOG_H_
#define SRC_LOG_H_

#include <stdbool.h>
#include <stdio.h>

#include "incidence.h"

#define PR_COLOR_DBG	"\x1B[36m"	/* Cyan */
#define PR_COLOR_INF	"\x1B[37m"	/* White */
#define PR_COLOR_WRN	"\x1B[33m"	/* Yellow */
#define PR_COLOR_ERR	"\x1B[31m"	/* Red */
#define PR_COLOR_CRT	"\x1B[35m"	/* Purple */
#define PR_COLOR_RST	"\x1B[0m"

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

/*
 * I know that the OpenBSD style guide says that we shouldn't declare our own
 * error printing functions, but we kind of need to do it:
 *
 * - It's convoluted to use err() and warn() on libcrypto errors.
 * - I was tasked with using syslog anyway, but the API is kind of limited
 *   (especially since vsyslog() is not portable.)
 * - We want to transparently always print offending file name.
 */

#if __GNUC__
#define CHECK_FORMAT(str, args) __attribute__((format(printf, str, args)))
#else
/*
 * No idea how this looks in other compilers.
 * It's safe to obviate since we're bound to see the warnings every time we use
 * GCC anyway.
 */
#define CHECK_FORMAT(str, args) /* Nothing */
#endif

/*
 * Only call this group of functions while you know there's only one thread.
 *
 * log_setup() is an incomplete initialization meant to be called when the
 * program starts. Logging can be performed after log_setup(), but it will use
 * default values.
 * log_init() finishes initialization by loading the user's intended config.
 * log_teardown() reverts initialization.
 */
int log_setup(void);
void log_start(void);
void log_teardown(void);

/*
 * Check if corresponding logging is enabled. You can use these to short-circuit
 * out of heavy logging code.
 */
bool log_val_enabled(unsigned int level);
bool log_op_enabled(unsigned int level);

/* == Operation logs == */

/* Status reports of no interest to the user. */
void pr_op_debug(const char *, ...) CHECK_FORMAT(1, 2);
/* Status reports likely useful to the user. */
void pr_op_info(const char *, ...) CHECK_FORMAT(1, 2);
/* Non-errors that suggest a problem. */
int pr_op_warn(const char *, ...) CHECK_FORMAT(1, 2);
/* Problematic situations that prevent Fort from doing its job. */
int pr_op_err(const char *, ...) CHECK_FORMAT(1, 2);
/* Like pr_op_err(), but it also prints a stack trace */
int pr_op_err_st(const char *format, ...) CHECK_FORMAT(1, 2);
/* Like pr_op_err(), except it prints libcrypto's error stack as well. */
int op_crypto_err(const char *, ...) CHECK_FORMAT(1, 2);


/* == Validation logs == */

/* Status reports of no interest to the user. */
void pr_val_debug(const char *, ...) CHECK_FORMAT(1, 2);
/* Status reports likely useful to the user. */
void pr_val_info(const char *, ...) CHECK_FORMAT(1, 2);
/* Issues that did not trigger RPKI object rejection. */
int pr_val_warn(const char *, ...) CHECK_FORMAT(1, 2);
/* Problems that trigger RPKI object rejection. */
int pr_val_err(const char *, ...) CHECK_FORMAT(1, 2);
/* Like pr_val_err(), except it prints libcrypto's error stack as well. */
int val_crypto_err(const char *, ...) CHECK_FORMAT(1, 2);

/*
 * Like pr_*_err(), specific to out-of-memory situations.
 * Also terminates the program.
 */
__dead void enomem_panic(void);
/* Programming errors */
__dead void pr_crit(const char *, ...) CHECK_FORMAT(1, 2);

int incidence(enum incidence_id, const char *, ...) CHECK_FORMAT(2, 3);

/*
 * Quick and dirty debugging messages.
 *
 * These are not meant to be uploaded; remember to delete them once the bug has
 * been found.
 */
#define DBG_COLOR "\x1B[32m" /* Green */
#define DBG_COLOR_RESET "\x1B[0m"
#define PR_DEBUG \
    printf(DBG_COLOR "%s:%d (%s())" DBG_COLOR_RESET "\n", \
    __FILE__, __LINE__, __func__)
#define PR_DEBUG_MSG(msg, ...) \
    printf(DBG_COLOR "%s:%d (%s()): " msg DBG_COLOR_RESET "\n", \
    __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#endif /* SRC_LOG_H_ */
