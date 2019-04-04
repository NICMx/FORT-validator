#include "primitive_reader.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>

#include "log.h"

static int read_exact(int, unsigned char *, size_t);
static int read_and_waste(int, unsigned char *, size_t, u_int32_t);
static int get_octets(unsigned char);
static void place_null_character(rtr_char *, size_t);

static int
read_exact(int fd, unsigned char *buffer, size_t buffer_len)
{
	ssize_t read_result;
	size_t offset;

	for (offset = 0; offset < buffer_len; offset += read_result) {
		read_result = read(fd, &buffer[offset], buffer_len - offset);
		if (read_result == -1) {
			warn("Client socket read interrupted");
			return -errno;
		}
		if (read_result == 0) {
			warnx("Stream ended mid-PDU.");
			return -EPIPE;
		}
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

/*
 * Consumes precisely @total_len bytes from @fd.
 * The first @str_len bytes are stored in @str.
 *
 * It is required that @str_len <= @total_len.
 */
static int
read_and_waste(int fd, unsigned char *str, size_t str_len, u_int32_t total_len)
{
#define TLEN 1024 /* "Trash length" */
	unsigned char *trash;
	size_t offset;
	int err;

	err = read_exact(fd, str, str_len);
	if (err)
		return err;

	if (str_len == total_len)
		return 0;

	trash = malloc(TLEN);
	if (trash == NULL)
		return pr_enomem();

	for (offset = str_len; offset < total_len; offset += TLEN) {
		err = read_exact(fd, trash,
		    (total_len - offset >= TLEN) ? TLEN : (total_len - offset));
		if (err)
			break;
	}

	free(trash);
	return err;
#undef TLEN
}

#define EINVALID_UTF8 -0xFFFF

/*
 * Returns the length (in octets) of the UTF-8 code point that starts with
 * octet @first_octet.
 */
static int
get_octets(unsigned char first_octet)
{
	if ((first_octet & 0x80) == 0)
		return 1;
	if ((first_octet >> 5) == 6) /* 0b110 */
		return 2;
	if ((first_octet >> 4) == 14) /* 0b1110 */
		return 3;
	if ((first_octet >> 3) == 30) /* 0b11110 */
		return 4;
	return EINVALID_UTF8;
}

/* This is just a cast. The barebones version is too cluttered. */
#define UCHAR(c) ((unsigned char *)c)

/*
 * This also sanitizes the string, BTW.
 * (Because it overrides the first invalid character with the null chara.
 * The rest is silently ignored.)
 */
static void
place_null_character(rtr_char *str, size_t len)
{
	rtr_char *null_chara_pos;
	rtr_char *cursor;
	int octet;
	int octets;

	/*
	 * This could be optimized by noticing that all byte continuations in
	 * UTF-8 start with 0b10. This means that we could start from the end
	 * of the string and move left until we find a valid character.
	 * But if we do that, we'd lose the sanitization. So this is better
	 * methinks.
	 */

	null_chara_pos = str;
	cursor = str;

	while (cursor < str + len - 1) {
		octets = get_octets(*UCHAR(cursor));
		if (octets == EINVALID_UTF8)
			break;
		cursor++;

		for (octet = 1; octet < octets; octet++) {
			/* Memory ends in the middle of this code point? */
			if (cursor >= str + len - 1)
				goto end;
			/* All continuation octets must begin with 0b10. */
			if ((*(UCHAR(cursor)) >> 6) != 2 /* 0b10 */)
				goto end;
			cursor++;
		}

		null_chara_pos = cursor;
	}

end:
	*null_chara_pos = '\0';
}

/*
 * Reads an RTR string from the file descriptor @fd. Returns the string as a
 * normal UTF-8 C string (NULL-terminated).
 *
 * Will consume the entire string from the stream, but @result can be
 * truncated. This is because RTR strings are technically allowed to be 4 GBs
 * long.
 *
 * The result is allocated in the heap. It will length 4096 characters at most.
 * (Including the NULL chara.)
 */
int
read_string(int fd, rtr_char **result)
{
	/* Actual string length claimed by the PDU, in octets. */
	u_int32_t full_length32; /* Excludes the null chara */
	u_int64_t full_length64; /* Includes the null chara */
	/*
	 * Actual length that we allocate. Octets.
	 * This exists because there might be value in truncating the string;
	 * full_length is a fucking 32-bit integer for some reason.
	 * Note that, because this is UTF-8 we're dealing with, this might not
	 * necessarily end up being the actual octet length of the final
	 * string; since our truncation can land in the middle of a code point,
	 * the null character might need to be shifted left slightly.
	 */
	size_t alloc_length; /* Includes the null chara */
	rtr_char *str;
	int err;

	err = read_int32(fd, &full_length32);
	if (err)
		return err;

	full_length64 = ((u_int64_t) full_length32) + 1;

	alloc_length = (full_length64 > 4096) ? 4096 : full_length64;
	str = malloc(alloc_length);
	if (!str)
		return -ENOMEM;

	err = read_and_waste(fd, UCHAR(str), alloc_length - 1, full_length32);
	if (err) {
		free(str);
		return err;
	}

	place_null_character(str, alloc_length);

	*result = str;
	return 0;
}
