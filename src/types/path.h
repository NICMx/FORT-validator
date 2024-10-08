#ifndef SRC_TYPES_PATH_H_
#define SRC_TYPES_PATH_H_

#include <stdbool.h>
#include <stddef.h>

// XXX rename
struct tokenizer {
	char const *str;
	size_t len;
};

void token_init(struct tokenizer *, char const *);
bool token_next(struct tokenizer *tkn);

char const *path_filename(char const *);
char *path_join(char const *, char const *);
char *path_njoin(char const *, char const *, size_t);

#endif /* SRC_TYPES_PATH_H_ */
