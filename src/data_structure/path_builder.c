#include "data_structure/path_builder.h"

#include <openssl/evp.h>

#include "alloc.h"
#include "log.h"
#include "crypto/hash.h"

#define SHA256_LEN (256 >> 3) /* 256 / 8, bits -> bytes */

/* These are arbitrary; feel free to change them. */
#ifndef INITIAL_CAPACITY /* Unit tests want to override this */
#define INITIAL_CAPACITY 128
#endif
#define MAX_CAPACITY 4096

void
pb_init(struct path_builder *pb)
{
	pb->string = pmalloc(INITIAL_CAPACITY);
	pb->len = 0;
	pb->capacity = INITIAL_CAPACITY;
	pb->error = 0;
}

/*
 * Returns true on success, false on failure.
 */
static bool
pb_grow(struct path_builder *pb, size_t total_len)
{
	if (total_len > MAX_CAPACITY) {
		free(pb->string);
		pr_val_err("Path too long: %zu > %u characters.", total_len,
		    MAX_CAPACITY);
		pb->error = ENOSPC;
		return false;
	}

	do {
		pb->capacity *= 2;
	} while (total_len > pb->capacity);

	pb->string = prealloc(pb->string, pb->capacity);
	return true;
}

static char const *
find_slash(char const *str, size_t len)
{
	char const *wall;

	for (wall = str + len; str < wall; str++)
		if (str[0] == '/')
			return str;

	return str;
}

/*
 * Do NOT include the null character in @addlen.
 * Assumes @addend needs no slashes.
 */
static void
add(struct path_builder *pb, char const *addend, size_t addlen)
{
	size_t total_len;

	total_len = pb->len + addlen;
	if (total_len > pb->capacity && !pb_grow(pb, total_len))
		return;

	memcpy(pb->string + pb->len, addend, addlen);
	pb->len += addlen;
}

static void
add_slashed(struct path_builder *pb, char const *addend, size_t addlen)
{
	/* Normalize first */
	switch (addlen) {
	case 1:
		if (addend[0] == '.')
			return;
		break;
	case 2:
		if (addend[0] == '.' && addend[1] == '.') {
			pb_pop(pb, false);
			return;
		}
		break;
	}

	/* Ok, do */
	if (pb->len > 0)
		add(pb, "/", 1);
	add(pb, addend, addlen);
}

/* Do NOT include the null character in @addlen. */
static void
pb_append_limited(struct path_builder *pb, char const *addend, size_t addlen)
{
	char const *wall;
	char const *next_slash;

	if (pb->error)
		return;

	do {
		for (wall = addend + addlen; addend < wall; addend++, addlen--)
			if (addend[0] != '/')
				break;
		next_slash = find_slash(addend, addlen);
		if (addend == next_slash)
			return;
		add_slashed(pb, addend, next_slash - addend);
		addlen -= next_slash - addend;
		addend = next_slash;
	} while (addlen > 0);
}

void
pb_append(struct path_builder *pb, char const *addend)
{
	pb_append_limited(pb, addend, strlen(addend));
}

void
pb_append_guri(struct path_builder *pb, struct rpki_uri *uri)
{
	char const *guri;
	char const *colon;
	size_t schema_len;

	if (pb->error)
		return;

	guri = uri_get_global(uri);

	colon = strstr(guri, ":");
	schema_len = colon - guri;
	pb_append_limited(pb, guri, schema_len);

	pb_append_limited(pb, colon + 3,
	    uri_get_global_len(uri) - schema_len - 3);
}

void
pb_append_uint(struct path_builder *pb, unsigned int num)
{
	size_t room;
	int num_len;

	if (pb->error)
		return;

	if (pb->len != 0 && pb->string[pb->len - 1] != '/')
		add(pb, "/", 1);

	room = pb->capacity - pb->len;
	num_len = snprintf(pb->string + pb->len, room, "%X", num);
	if (num_len < 0)
		goto bad_print;
	if (num_len >= room) {
		if (!pb_grow(pb, pb->len + num_len + 1))
			return;

		room = pb->capacity - pb->len;
		num_len = snprintf(pb->string + pb->len, room, "%X", num);
		if (num_len < 0)
			goto bad_print;
		if (num_len >= room)
			pr_crit("pb: %d %zu", num_len, room);
	}

	pb->len += num_len;
	return;

bad_print:
	free(pb->string);
	pb->error = EIO; /* num_len is not necessarily an error code */
}

/* Removes the last component added. */
void
pb_pop(struct path_builder *pb, bool fatal)
{
	size_t i;

	if (pb->error)
		return;
	if (pb->len == 0) {
		if (fatal)
			pr_crit("Programming error: Attempting to pop empty path builder");
		free(pb->string);
		pb->error = -pr_val_err("Path cannot '..' over the root.");
		return;
	}

	for (i = pb->len - 1; i >= 1; i--) {
		if (pb->string[i] == '/') {
			pb->len = i;
			return;
		}
	}

	pb->len = (pb->string[0] == '/') && (pb->len > 1);
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

	if (pb->error)
		return;

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

/*
 * Returns @pb's current accumulated path. Do not free it.
 * Result is a temporary pointer; it becomes junk if you call any other pb
 * functions on @pb afterwards.
 */
int
pb_peek(struct path_builder *pb, char const **result)
{
	add(pb, "\0", 1);
	if (pb->error)
		return pb->error;

	*result = pb->string;
	pb->len--;
	return 0;
}

/* Should not be called more than once. */
int
pb_compile(struct path_builder *pb, char **result)
{
	add(pb, "\0", 1);
	if (pb->error)
		return pb->error;

	*result = pb->string;
	return 0;
}

void
pb_cancel(struct path_builder *pb)
{
	free(pb->string);
}
