#include "stream.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#include "alloc.h"
#include "log.h"

void
rstream_init(struct read_stream *stream, int fd, size_t initial_capacity)
{
	stream->fd = fd;
	stream->buffer = pmalloc(initial_capacity);
	stream->len = 0;
	stream->capacity = initial_capacity;
}

void
rstream_close(struct read_stream *stream, bool do_close)
{
	if (stream->fd == -1)
		return;

	if (do_close)
		close(stream->fd);
	free(stream->buffer);
	stream->fd = -1;
}

/*
 * Reads until exactly @len bytes (sleeping if necessary), EOS or error.
 * @stream's capacity must be >= len.
 *
 * Returns:
 * - >= 0: Number of bytes read (< @len only if EOS reached).
 * - < 0: error; remove sign for proper code.
 */
int
rstream_full_read(struct read_stream *stream, size_t len)
{
	size_t offset;
	ssize_t rd;

	if (stream->buffer == NULL || stream->capacity < len)
		return -ENOSPC;

	for (offset = 0; offset < len; offset += rd) {
		rd = read(stream->fd, stream->buffer + offset, len - offset);
		if (rd < 0)
			return -errno;
		if (rd == 0)
			break;
	}

	return offset;
}

/* Full write (sleeps if necessary) or error. */
int
stream_full_write(int fd, unsigned char const *buf, size_t len)
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
