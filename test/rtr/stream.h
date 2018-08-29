#ifndef TEST_RTR_STREAM_H_
#define TEST_RTR_STREAM_H_

#include <stddef.h>

#include "common.h"

__BEGIN_DECLS
int write_exact(int, unsigned char *, size_t);
int buffer2fd(unsigned char *, size_t);
__END_DECLS

#endif /* TEST_RTR_STREAM_H_ */
