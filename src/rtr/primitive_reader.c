#include "primitive_reader.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "log.h"

static int get_octets(unsigned char);
static void place_null_character(rtr_char *, size_t);

/**
 * Reads exactly @buffer_len bytes from @buffer, erroring if this goal cannot be
 * met.
 *
 * If @allow_end is true, will allow immediate EOF in place of the buffer bytes.
 * (Though all this really means is that the corresponding warning message will
 * not be printed, which is perfectly fine as far as the only current caller is
 * concerned.)
 *
 * Returns 0 if exactly @buffer_len bytes could be read.
 */
static int
read_exact(int fd, unsigned char *buffer, size_t buffer_len, bool allow_eof)
{
	ssize_t read_result;
	size_t offset;

	for (offset = 0; offset < buffer_len; offset += read_result) {
		read_result = read(fd, &buffer[offset], buffer_len - offset);
		if (read_result == -1)
			return -pr_errno(errno, "Client socket read interrupted");

		if (read_result == 0) {
			if (!allow_eof)
				pr_warn("Stream ended mid-PDU.");
			return -EPIPE;
		}

		allow_eof = false;
	}

	return 0;
}

/**
 * BTW: I think it's best not to use sizeof for @size, because it risks
 * including padding.
 */
int
pdu_reader_init(struct pdu_reader *reader, int fd, unsigned char *buffer,
    size_t size, bool allow_eof)
{
	reader->buffer = buffer;
	reader->size = size;
	return read_exact(fd, reader->buffer, size, allow_eof);
}

__dead static void
insufficient_bytes(void)
{
	pr_crit("Attempted to read past the end of a PDU Reader.");
}

int
read_int8(struct pdu_reader *reader, uint8_t *result)
{
	if (reader->size < 1)
		insufficient_bytes();

	*result = reader->buffer[0];
	reader->buffer++;
	reader->size--;
	return 0;
}

/** Big Endian. */
int
read_int16(struct pdu_reader *reader, uint16_t *result)
{
	if (reader->size < 2)
		insufficient_bytes();

	*result = (((uint16_t)reader->buffer[0]) << 8)
	        | (((uint16_t)reader->buffer[1])     );
	reader->buffer += 2;
	reader->size -= 2;
	return 0;
}

/** Big Endian. */
int
read_int32(struct pdu_reader *reader, uint32_t *result)
{
	if (reader->size < 4)
		insufficient_bytes();

	*result = (((uint32_t)reader->buffer[0]) << 24)
	        | (((uint32_t)reader->buffer[1]) << 16)
	        | (((uint32_t)reader->buffer[2]) <<  8)
	        | (((uint32_t)reader->buffer[3])      );
	reader->buffer += 4;
	reader->size -= 4;
	return 0;
}

int
read_in_addr(struct pdu_reader *reader, struct in_addr *result)
{
	return read_int32(reader, &result->s_addr);
}

int
read_in6_addr(struct pdu_reader *reader, struct in6_addr *result)
{
	unsigned int i;
	int error;

	for (i = 0; i < 16; i++) {
		error = read_int8(reader, &result->s6_addr[i]);
		if (error)
			return error;
	}

	return 0;
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

	while (cursor < str + len) {
		octets = get_octets(*UCHAR(cursor));
		if (octets == EINVALID_UTF8)
			break;
		cursor++;

		for (octet = 1; octet < octets; octet++) {
			/* Memory ends in the middle of this code point? */
			if (cursor >= str + len)
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
read_string(struct pdu_reader *reader, uint32_t string_len, rtr_char **result)
{
	/* Actual string length claimed by the PDU, in octets. */
	rtr_char *string;

	if (reader->size < string_len)
		return pr_err("Erroneous PDU's error message is larger than its slot in the PDU.");

	/*
	 * Ok. Since the PDU size is already sanitized, string_len is guaranteed
	 * to be relatively small now.
	 */

	string = malloc(string_len + 1); /* Include NULL chara. */
	if (!string)
		return -ENOMEM;

	memcpy(string, reader->buffer, string_len);
	reader->buffer += string_len;
	reader->size -= string_len;

	place_null_character(string, string_len);

	*result = string;
	return 0;
}

int
read_bytes(struct pdu_reader *reader, unsigned char *result, size_t num)
{
	if (reader->size < num)
		insufficient_bytes();

	memcpy(result, reader->buffer, num);
	reader->buffer += num;
	reader->size -= num;
	return 0;
}
