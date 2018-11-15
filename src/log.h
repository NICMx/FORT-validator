#ifndef SRC_LOG_H_
#define SRC_LOG_H_

#include "state.h"

void pr_debug(struct validation *, const char *, ...);
void pr_debug_add(struct validation *, const char *, ...);
void pr_debug_rm(struct validation *, const char *, ...);

void pr_err(struct validation *, const char *, ...);
int pr_errno(struct validation *, int, const char *, ...);
int crypto_err(struct validation *, const char *, ...);

#define PR_DEBUG(msg) \
    printf("%s:%d (%s()): " msg "\n", __FILE__, __LINE__, __func__)

#endif /* SRC_LOG_H_ */
