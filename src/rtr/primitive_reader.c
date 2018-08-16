#include "primitive_reader.h"

#include <err.h>
#include <errno.h>
#include <unistd.h>

static int
read_exact(int fd, unsigned char *buffer, size_t length)
{
	int n, m;
	int err;

	for (n = 0; n < length;) {
		m = read(fd, &buffer[n], length - n);
		if (m < 0) {
			err = errno;
			warn("Client socket read interrupted");
			return err;
		}

		if (m == 0 && n == 0) {
			/* Stream ended gracefully. */
			return 0;
		}

		if (m == 0) {
			err = -EPIPE;
			warn("Stream ended mid-PDU");
			return err;
		}

		n += m;
	}

	return 0;
}

int
read_int8(int fd, u_int8_t *result)
{
	return read_exact(fd, result, sizeof(u_int8_t));
}

/** Big Endian. */
int
read_int16(int fd, u_int16_t *result)
{
	unsigned char buffer[2];
	int err;

	err = read_exact(fd, buffer, sizeof(buffer));
	if (err)
		return err;

	*result = (((u_int16_t)buffer[0]) << 8) | ((u_int16_t)buffer[1]);
	return 0;
}

/** Big Endian. */
int
read_int32(int fd, u_int32_t *result)
{
	unsigned char buffer[4];
	int err;

	err = read_exact(fd, buffer, sizeof(buffer));
	if (err)
		return err;

	*result = (((u_int32_t)buffer[0]) << 24)
	        | (((u_int32_t)buffer[1]) << 16)
	        | (((u_int32_t)buffer[2]) <<  8)
	        | (((u_int32_t)buffer[3])      );
	return 0;
}

int
read_in_addr(int fd, struct in_addr *result)
{
	return read_int32(fd, &result->s_addr);
}

int
read_in6_addr(int fd, struct in6_addr *result)
{
	return read_int32(fd, &result->s6_addr32[0])
	    || read_int32(fd, &result->s6_addr32[1])
	    || read_int32(fd, &result->s6_addr32[2])
	    || read_int32(fd, &result->s6_addr32[3]);
}

int
read_string(int fd, char **result)
{
	u_int32_t length;
	int err;

	err = read_int32(fd, &length);
	if (err)
		return err;

	/*
	 * TODO the RFC doesn't say if the length is in bytes, code points or
	 * graphemes...
	 */
	*result = NULL;
	return 0;
}
