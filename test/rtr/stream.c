#include "stream.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Writes exactly @length bytes from @buffer to the file descriptor @fd.
 * All or nothing.
 *
 * The result is zero on success, nonzero on failure.
 */
int
write_exact(int fd, unsigned char *buffer, size_t length)
{
	size_t written;
	int written_now;

	for (written = 0; written < length; written += written_now) {
		written_now = write(fd, buffer + written, length - written);
		if (written_now == -1)
			return errno;
	}

	return 0;
}

/*
 * "Converts" the buffer @buffer (sized @size) to a file descriptor (FD).
 * You will get @buffer if you `read()` the FD.
 *
 * If the result is not negative, then you're receiving the resulting FD.
 * If the result is negative, it's an error code.
 *
 * Note that you need to close the FD when you're done reading it.
 */
int
buffer2fd(unsigned char *buffer, size_t size)
{
	int fd[2];
	int err;

	if (pipe(fd) == -1) {
		err = errno;
		warn("Pipe creation failed");
		return -abs(err);
	}

	err = write_exact(fd[1], buffer, size);
	close(fd[1]);
	if (err) {
		errno = err;
		warn("Pipe write failed");
		close(fd[0]);
		return -abs(err);
	}

	return fd[0];
}
