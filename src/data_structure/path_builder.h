#ifndef SRC_DATA_STRUCTURE_PATH_BUILDER_H_
#define SRC_DATA_STRUCTURE_PATH_BUILDER_H_

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct path_builder {
	char *string;
	size_t len; /* Includes the null chara */
	size_t capacity;
};

void pb_init(struct path_builder *);
int pb_init_cache(struct path_builder *, char const *, char const *);

/*
 * The appends are atomic.
 * They are also naive; they don't collapse `.`, `..` nor slashes.
 */

int pb_appendn(struct path_builder *, char const *, size_t);
int pb_append(struct path_builder *, char const *);
int pb_append_u32(struct path_builder *, uint32_t);

int pb_pop(struct path_builder *, bool);

void pb_reverse(struct path_builder *);

void pb_cleanup(struct path_builder *);

#endif /* SRC_DATA_STRUCTURE_PATH_BUILDER_H_ */
