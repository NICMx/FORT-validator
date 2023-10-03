#define _XOPEN_SOURCE 500 /* snprintf() */

#include "data_structure/path_builder.h"

#include <errno.h>

#include "alloc.h"
#include "log.h"
#include "crypto/hash.h"

#define SHA256_LEN (256 >> 3) /* 256 / 8, bits -> bytes */

/* These are arbitrary; feel free to change them. */
#ifndef INITIAL_CAPACITY /* Unit tests want to override this */
#define INITIAL_CAPACITY 128u
#endif
#define MAX_CAPACITY 4096u

void
pb_init(struct path_builder *pb)
{
	pb->string = pmalloc(INITIAL_CAPACITY);
	pb->string[0] = 0;
	pb->len = 0;
	pb->capacity = INITIAL_CAPACITY;
}

static int
pb_grow(struct path_builder *pb, size_t total_len, char const *addend)
{
	if (total_len > MAX_CAPACITY) {
		pr_val_err("Unable to concatenate '%.32s' (might be truncated) to path '%s': Path too long (%zu > %u)",
		    addend, pb->string, total_len, MAX_CAPACITY);
		return ENOSPC;
	}

	do {
		pb->capacity *= 2;
	} while (total_len > pb->capacity);

	pb->string = prealloc(pb->string, pb->capacity);
	return 0;
}

int
pb_appendn(struct path_builder *pb, char const *addend, size_t addlen)
{
	size_t total_len;
	bool add_slash;
	int error;

	if (addlen == 0)
		return 0;

	add_slash = (pb->len != 0);
	if (add_slash)
		addlen++;

	total_len = pb->len + addlen + 1;
	if (total_len > pb->capacity) {
		error = pb_grow(pb, total_len, addend);
		if (error)
			return error;
	}

	if (add_slash) {
		pb->string[pb->len] = '/';
		memcpy(pb->string + pb->len + 1, addend, addlen);
	} else {
		memcpy(pb->string + pb->len, addend, addlen);
	}

	pb->len += addlen;
	pb->string[pb->len] = 0;

	return 0;
}

int
pb_append(struct path_builder *pb, char const *addend)
{
	return (addend != NULL)
	    ? pb_appendn(pb, addend, strlen(addend))
	    : 0;
}

int
pb_append_u32(struct path_builder *pb, uint32_t num)
{
#define MAX_STRLEN 9 /* 8 hexadecimal digits plus null chara */
	char buffer[MAX_STRLEN];
	int num_len;

	num_len = snprintf(buffer, MAX_STRLEN, "%X", num);
	if (num_len < 0) {
		pr_val_err("Cannot stringify number '%u': Unknown cause. Error code might be %d.",
		    num, num_len);
		return EIO; /* num_len is not necessarily an error code */
	}
	if (num_len >= MAX_STRLEN)
		pr_crit("pb: Number %u requires %d digits", num, num_len);

	return pb_appendn(pb, buffer, num_len);
}

/* Removes the last component added. */
int
pb_pop(struct path_builder *pb, bool fatal)
{
	size_t i;

	if (pb->len == 0 || (pb->len == 1 && pb->string[0] == '/')) {
		if (fatal)
			pr_crit("Programming error: Attempting to pop empty path builder");
		return -pr_val_err("Path cannot '..' over the root.");
	}

	for (i = pb->len - 1; i >= 1; i--) {
		if (pb->string[i] == '/') {
			pb->string[i] = 0;
			pb->len = i;
			return 0;
		}
	}

	if (pb->string[0] == '/') {
		pb->string[1] = 0;
		pb->len = 1;
	} else {
		pb->string[0] = 0;
		pb->len = 0;
	}
	return 0;
}

static void
reverse_string(char *str, size_t len)
{
	char *b, *e; /* beginning, end */
	char tmp;

	for (b = str, e = str + len - 1; b < e; b++, e--) {
		tmp = *b;
		*b = *e;
		*e = tmp;
	}
}

/* Turns ab/cd/ef/gh into gh/ef/cd/ab. */
void
pb_reverse(struct path_builder *pb)
{
	size_t min;
	size_t max;

	reverse_string(pb->string, pb->len);

	min = 0;
	for (max = 1; max < pb->len; max++) {
		if (pb->string[max] == '/') {
			reverse_string(&pb->string[min], max - min);
			max++;
			min = max;
		}
	}
	reverse_string(&pb->string[min], pb->len - min);
}

void
pb_cleanup(struct path_builder *pb)
{
	free(pb->string);
}
