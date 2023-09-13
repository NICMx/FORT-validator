#ifndef SRC_DATA_STRUCTURE_PATH_BUILDER_H_
#define SRC_DATA_STRUCTURE_PATH_BUILDER_H_

/* FIXME add support for absolute paths */

#include <stdbool.h>
#include <stddef.h>
#include "types/uri.h"

struct path_builder {
	char *string;
	size_t len;
	size_t capacity;
	int error;
};

void pb_init(struct path_builder *);

/*
 * Note, the append()s merge slashes:
 *
 * 	a + b = a/b
 * 	a/ + b = a/b
 * 	a + /b = a/b
 * 	a/ + /b = a/b
 * 	a// + ///b = a/b
 * 	a///b + c//d = a/b/c/d
 */

void pb_append(struct path_builder *, char const *);
void pb_append_guri(struct path_builder *, struct rpki_uri *);
void pb_append_uint(struct path_builder *, unsigned int);

void pb_pop(struct path_builder *, bool);

void pb_reverse(struct path_builder *);

int pb_peek(struct path_builder *, char const **);
int pb_compile(struct path_builder *, char **);

void pb_cancel(struct path_builder *);

#endif /* SRC_DATA_STRUCTURE_PATH_BUILDER_H_ */
