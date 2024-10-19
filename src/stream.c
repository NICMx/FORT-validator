#include "stream.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

void
read_stream_init(struct read_stream *stream, int fd)
{
	stream->fd = fd;
	stream->buffer = pmalloc(256);
	stream->capacity = 256;
}

void
read_stream_close(struct read_stream *stream)
{
	close(stream->fd);
	free(stream->buffer);
}

/*
 * Full read or error.
 *
 * Nonzero: error
 * 0, stream->buffer != NULL: Success
 * 0, stream->buffer == NULL: EOF
 */
static int
full_read(struct read_stream *stream, size_t len)
{
	ssize_t rd;
	size_t offset;

	if (stream->buffer == NULL)
		return 0;

	offset = 0;
	do {
		rd = read(stream->fd, stream->buffer + offset, len);
		if (rd < 0)
			return errno;
		if (rd == 0) {
			free(stream->buffer);
			stream->buffer = NULL;
			stream->capacity = 0;
			return 0;
		}
		if (rd == len)
			return 0;
		if (rd > len)
			pr_crit("rd > len: %zd > %zu", rd, len);

		len -= rd;
		offset += rd;
	} while (true);
}

/* Full write or error. */
int
full_write(int fd, unsigned char const *buf, size_t len)
{
	ssize_t wr;
	size_t offset;

	offset = 0;
	do {
		wr = write(fd, buf + offset, len);
		if (wr < 0)
			return errno;
		if (wr > len)
			pr_crit("wr > len: %zd > %zu", wr, len);
		len -= wr;
		offset += wr;
	} while (len > 0);

	return 0;
}

/* @value -1 means "EOF". */
static int
read_ssize_t(struct read_stream *stream, ssize_t *value)
{
	int error;

	error = full_read(stream, 2);
	if (error)
		return error;

	*value = stream->buffer
	    ? ((stream->buffer[0] << 8) | stream->buffer[1])
	    : -1;
	return 0;
}

static int
write_size_t(int fd, size_t value)
{
	unsigned char buf[2];

	if (value > 1024)
		return ENOSPC;

	buf[0] = (value >> 8) & 0xFF;
	buf[1] = value & 0xFF;

	return full_write(fd, buf, 2);
}

int
read_string(struct read_stream *stream, char **result)
{
	ssize_t len;
	int error;

	error = read_ssize_t(stream, &len);
	if (error)
		return error;
	if (len == -1) {
		*result = NULL;
		return 0;
	}

	if (len > stream->capacity) {
		do {
			stream->capacity *= 2;
		} while (len > stream->capacity);
		stream->buffer = prealloc(stream->buffer, stream->capacity);
	}

	error = full_read(stream, len);
	if (error)
		return error;
	*result = stream->buffer ? pstrdup((char *)stream->buffer) : NULL;
	return 0;
}

int
write_string(int fd, char const *str)
{
	size_t len;
	int error;

	len = strlen(str) + 1;

	error = write_size_t(fd, len);
	if (error)
		return error;

	return full_write(fd, (unsigned char const *) str, len);
}
