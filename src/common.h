#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

#include <string.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define warnxerror0(error, msg) \
	warnx(msg ": %s", strerror(error))
#define warnxerrno0(msg) \
	warnxerror0(errno, msg)
#define warnxerror(error, msg, ...) \
	warnx(msg ": %s", ##__VA_ARGS__, strerror(error))
#define warnxerrno(msg, ...) \
	warnxerror(errno, msg, ##__VA_ARGS__)

#define pr_debug(msg, ...) printf("Debug: " msg "\n", ##__VA_ARGS__);

#endif /* SRC_RTR_COMMON_H_ */
