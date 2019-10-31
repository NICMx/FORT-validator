#ifndef SRC_LOG_H_
#define SRC_LOG_H_

#include <stdbool.h>
#include "incidence/incidence.h"

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

/* Only call this group of functions when you know there's only one thread. */
void log_setup(void);
void log_start(void);
void log_teardown(void);


/*
 * Please note: The log message (excluding pr_errno's strerror and libcrypto's
 * error stack) cannot exceed 512 bytes at present.
 */

/*
 * Check if debug or info are enabled, useful to avoid boilerplate code
 */
bool log_debug_enabled(void);
bool log_info_enabled(void);

/* Debug messages, useful for devs or to track a specific problem */
void pr_debug(const char *, ...) CHECK_FORMAT(1, 2);
/* Non-errors deemed useful to the user. */
void pr_info(const char *, ...) CHECK_FORMAT(1, 2);
/* Issues that did not trigger RPKI object rejection. */
int pr_warn(const char *, ...) CHECK_FORMAT(1, 2);
/* Errors that trigger RPKI object rejection. */
int pr_err(const char *, ...) CHECK_FORMAT(1, 2);
int pr_errno(int, const char *, ...) CHECK_FORMAT(2, 3);
int crypto_err(const char *, ...) CHECK_FORMAT(1, 2);
int pr_enomem(void);
/* Programming errors */
__dead void pr_crit(const char *, ...) CHECK_FORMAT(1, 2);

int incidence(enum incidence_id, const char *, ...) CHECK_FORMAT(2, 3);

#define PR_DEBUG printf("%s:%d (%s())\n", __FILE__, __LINE__, __func__)
#define PR_DEBUG_MSG(msg, ...) printf("%s:%d (%s()): " msg "\n", \
    __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#endif /* SRC_LOG_H_ */
