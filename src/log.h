#ifndef SRC_LOG_H_
#define SRC_LOG_H_

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

#else

#define pr_debug(...)
#define pr_debug_add(...)
#define pr_debug_rm(...)
#define pr_debug_prefix

#endif

void pr_info(const char *, ...) CHECK_FORMAT(1, 2);
int pr_warn(const char *, ...) CHECK_FORMAT(1, 2);
int pr_err(const char *, ...) CHECK_FORMAT(1, 2);
int pr_errno(int, const char *, ...) CHECK_FORMAT(2, 3);
int crypto_err(const char *, ...) CHECK_FORMAT(1, 2);
int pr_enomem(void);
int pr_crit(const char *, ...) CHECK_FORMAT(1, 2);

#define PR_DEBUG printf("%s:%d (%s())\n", __FILE__, __LINE__, __func__)
#define PR_DEBUG_MSG(msg, ...) printf("%s:%d (%s()): " msg "\n", \
    __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#endif /* SRC_LOG_H_ */
