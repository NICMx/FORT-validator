#ifndef TEST_RTR_STREAM_H_
#define TEST_RTR_STREAM_H_

#include <stddef.h>

int write_exact(int, unsigned char *, size_t);
int buffer2fd(unsigned char *, size_t);

#endif /* TEST_RTR_STREAM_H_ */
