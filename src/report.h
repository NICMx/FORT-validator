#ifndef SRC_REPORT_H_
#define SRC_REPORT_H_

#include <stdarg.h>
#include <stdbool.h>

int report_enable(void);	/* pr_wrn and pr_errs now send to report */
bool report_enabled(void);
void report(char const *, char const *, va_list);
void report_disable(void);	/* pr_wrn and pr_errs go back to logs */

#endif /* SRC_REPORT_H_ */
