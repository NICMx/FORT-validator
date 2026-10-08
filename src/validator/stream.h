#ifndef VALIDATOR_STREAM_H_
#define VALIDATOR_STREAM_H_

#include <stdbool.h>
#include <stddef.h>

struct read_stream {
	int fd;
	unsigned char *buffer;
	size_t len;
	size_t capacity;
};

void rstream_init(struct read_stream *, int, size_t);
int rstream_full_read(struct read_stream *, size_t);
void rstream_close(struct read_stream *, bool);

int stream_full_write(int, unsigned char const *, size_t);

#endif /* VALIDATOR_STREAM_H_ */
