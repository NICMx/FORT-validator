#ifndef SRC_LOG_H_
#define SRC_LOG_H_

#include <sys/cdefs.h>
#include "incidence/incidence.h"

/*
 * __dead is supposed to be defined in sys/cdefs.h, but is apparently not
 * portable.
 */
#ifndef __dead
#if __GNUC__
#define __dead __attribute__ ((noreturn))
#else
#define __dead
#endif
#endif

/*
 * I know that the OpenBSD style guide says that we shouldn't declare our own
 * error printing functions, but we kind of need to do it:
 *
 * - It's convoluted to use err() and warn() on libcrypto errors.
 * - If debug is enabled, we want the error messages to be printed as a tree
 *   to ease debugging.
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

void pr_indent_add(void);
void pr_indent_rm(void);

#ifdef DEBUG

void pr_debug(const char *, ...) CHECK_FORMAT(1, 2);
void pr_debug_add(const char *, ...) CHECK_FORMAT(1, 2);
void pr_debug_rm(const char *, ...) CHECK_FORMAT(1, 2);
void pr_debug_prefix(void);
void pr_debug_suffix(void);

#else

/*
 * I want to define these as empty, but then we get compiler warnings on
 *
 * ```
 * else
 * 	pr_debug(...);
 * ```
 *
 * Oh well.
 */

#define pr_debug(...) do {} while (0)
#define pr_debug_add(...) do {} while (0)
#define pr_debug_rm(...) do {} while (0)

#endif

void pr_info(const char *, ...) CHECK_FORMAT(1, 2);
int pr_warn(const char *, ...) CHECK_FORMAT(1, 2);
int pr_err(const char *, ...) CHECK_FORMAT(1, 2);
int pr_errno(int, const char *, ...) CHECK_FORMAT(2, 3);
int crypto_err(const char *, ...) CHECK_FORMAT(1, 2);
int pr_enomem(void);
__dead void pr_crit(const char *, ...) CHECK_FORMAT(1, 2);

int incidence(enum incidence_id, const char *, ...) CHECK_FORMAT(2, 3);

#define PR_DEBUG printf("%s:%d (%s())\n", __FILE__, __LINE__, __func__)
#define PR_DEBUG_MSG(msg, ...) printf("%s:%d (%s()): " msg "\n", \
    __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#endif /* SRC_LOG_H_ */
