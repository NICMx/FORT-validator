#ifndef SRC_STREAM_H_
#define SRC_STREAM_H_

struct read_stream {
	int fd;
	unsigned char *buffer;
	size_t capacity;
};

void read_stream_init(struct read_stream *, int);
void read_stream_close(struct read_stream *);

int full_write(int, unsigned char const *, size_t);

/* NULL means "EOF". */
int read_string(struct read_stream *, char **);
int write_string(int, char const *);

#endif /* SRC_STREAM_H_ */
