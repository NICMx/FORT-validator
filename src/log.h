#ifndef SRC_LOG_H_
#define SRC_LOG_H_

#include "state.h"

void pr_debug(const char *, ...);
void pr_debug_add(const char *, ...);
void pr_debug_rm(const char *, ...);

void pr_err(const char *, ...);
int pr_errno(int, const char *, ...);
int crypto_err(struct validation *, const char *, ...);

#define PR_DEBUG printf("%s:%d (%s())\n", __FILE__, __LINE__, __func__)

#endif /* SRC_LOG_H_ */
