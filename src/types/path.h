#ifndef SRC_TYPES_PATH_H_
#define SRC_TYPES_PATH_H_

#include <stdbool.h>
#include <netdb.h>

// XXX rename
struct tokenizer {
	char const *str;
	size_t len;
};

void token_init(struct tokenizer *, char const *);
bool token_next(struct tokenizer *tkn);

struct path_builder {
	char *string;
	size_t len; /* Includes the null chara */
	size_t capacity;
};

void __pb_init(struct path_builder *, size_t);
#define pb_init(pb) __pb_init(pb, 0)
int pb_init_cache(struct path_builder *, char const *);

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

char *path_parent(char const *);
char *path_childn(char const *, char const *, size_t);
char *join_paths(char const *, char const *);

#endif /* SRC_TYPES_PATH_H_ */
