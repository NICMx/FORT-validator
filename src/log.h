#ifndef SRC_LOG_H_
#define SRC_LOG_H_

#include <stdbool.h>
#include <stdio.h>

#define PR_COLOR_DBG	"\x1B[36m"	/* Cyan */
#define PR_COLOR_CLT	"\x1B[34m"	/* Blue */
#define PR_COLOR_TRC	"\x1B[32m"	/* Green */
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

#if __GNUC__
#define CHECK_FORMAT(str, args) __attribute__((format(printf, str, args)))
#else
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

#define pr_clutter_enabled() false
#define pr_clutter(...)

void pr_trc(const char *, ...) CHECK_FORMAT(1, 2);
void pr_inf(const char *, ...) CHECK_FORMAT(1, 2);
int pr_wrn(const char *, ...) CHECK_FORMAT(1, 2);
int pr_err(const char *, ...) CHECK_FORMAT(1, 2);
/* Like pr_err(), but also prints libcrypto's error stack */
int pr_crypto_err(const char *, ...) CHECK_FORMAT(1, 2);
int pr_crit(const char *format, ...) CHECK_FORMAT(1, 2);
__dead void pr_panic(const char *, ...) CHECK_FORMAT(1, 2);
__dead void enomem_panic(void); /* Out of memory */

#define PR_DBG(msg, ...) \
    printf(PR_COLOR_DBG "%s:%d (%s()): " msg PR_COLOR_RST "\n", \
        __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define PR_HELLO \
    printf(PR_COLOR_DBG "%s:%d (%s())" PR_COLOR_RST "\n", \
        __FILE__, __LINE__, __func__)

#endif /* SRC_LOG_H_ */
