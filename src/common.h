#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <openssl/x509v3.h>

/* "I think that this is not supposed to be implemented." */
#define ENOTSUPPORTED 3172
/* "I haven't implemented this yet." */
#define ENOTIMPLEMENTED 3173

extern char const *repository;
extern int NID_rpkiManifest;
extern int NID_rpkiNotify;

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

#define warnxerror0(error, msg) \
	warnx(msg ": %s", strerror(error))
#define warnxerrno0(msg) \
	warnxerror0(errno, msg)
#define warnxerror(error, msg, ...) \
	warnx(msg ": %s", ##__VA_ARGS__, strerror(error))
#define warnxerrno(msg, ...) \
	warnxerror(errno, msg, ##__VA_ARGS__)

#define pr_debug(msg, ...) {			\
	printf("DBG: ");			\
	pr_indent();				\
	printf(msg "\n", ##__VA_ARGS__);	\
}
#define pr_debug_add(msg, ...) {		\
	pr_debug(msg, ##__VA_ARGS__);		\
	pr_add_indent();			\
}
#define pr_debug_rm(msg, ...) {			\
	pr_rm_indent();				\
	pr_debug(msg, ##__VA_ARGS__);		\
}

#define pr_debug0(msg) {			\
	printf("DBG: ");			\
	pr_indent();				\
	printf(msg "\n");			\
}
#define pr_debug0_add(msg) {			\
	pr_debug0(msg);				\
	pr_add_indent();			\
}
#define pr_debug0_rm(msg) {			\
	pr_rm_indent();				\
	pr_debug0(msg);				\
}

void pr_indent(void);
void pr_add_indent(void);
void pr_rm_indent(void);

bool file_has_extension(char const *, char const *);
int uri_g2l(char const *guri, char **result);
int gn2uri(GENERAL_NAME *, char const **);

#endif /* SRC_RTR_COMMON_H_ */
