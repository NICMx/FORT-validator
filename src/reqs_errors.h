#ifndef SRC_REQS_ERRORS_H_
#define SRC_REQS_ERRORS_H_

#include <stdbool.h>

int reqs_errors_init(void);
void reqs_errors_cleanup(void);

int reqs_errors_add_uri(char const *);
void reqs_errors_rem_uri(char const *);

bool reqs_errors_log_uri(char const *);

void reqs_errors_log_summary(void);

#endif /* SRC_REQS_ERRORS_H_ */
