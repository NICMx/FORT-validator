#ifndef _SRC_COMMON_H_
#define _SRC_COMMON_H_

#include <string.h>

/* __BEGIN_DECLS should be used at the beginning of your declarations,
   so that C++ compilers don't mangle their names.  Use __END_DECLS at
   the end of C declarations. */
#undef __BEGIN_DECLS
#undef __END_DECLS
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS /* empty */
# define __END_DECLS /* empty */
#endif

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define EUNIMPLEMENTED 566456

#define warnxerror0(error, msg) \
	warnx(msg ": %s", strerror(error))
#define warnxerrno0(msg) \
	warnxerror0(errno, msg)
#define warnxerror(error, msg, ...) \
	warnx(msg ": %s", ##__VA_ARGS__, strerror(error))
#define warnxerrno(msg, ...) \
	warnxerror(errno, msg, ##__VA_ARGS__)

#define pr_debug0(msg) printf("Debug: " msg "\n");
#define pr_debug(msg, ...) printf("Debug: " msg "\n", ##__VA_ARGS__);

#endif /* _SRC_COMMON_H_ */
