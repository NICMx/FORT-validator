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

void pr_debug(const char *, ...);
void pr_debug_add(const char *, ...);
void pr_debug_rm(const char *, ...);
void pr_debug_prefix(void);

int pr_err(const char *, ...);
int pr_errno(int, const char *, ...);
int crypto_err(const char *, ...);
int pr_enomem(void);

int pr_crit(const char *, ...);

#define PR_DEBUG printf("%s:%d (%s())\n", __FILE__, __LINE__, __func__)
#define PR_DEBUG_MSG(msg, ...) printf("%s:%d (%s()): " msg "\n", \
    __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#endif /* SRC_LOG_H_ */
