#ifndef SRC_DATA_STRUCTURE_PATH_BUILDER_H_
#define SRC_DATA_STRUCTURE_PATH_BUILDER_H_

#include <stddef.h>

struct path_builder {
	char *string;
	size_t len;
	size_t capacity;
	int error;
};

void path_init(struct path_builder *);

void path_append(struct path_builder *, char const *);
void path_append_limited(struct path_builder *, char const *, size_t);
void path_append_url(struct path_builder *, char const *);

int path_compile(struct path_builder *, char **);

#endif /* SRC_DATA_STRUCTURE_PATH_BUILDER_H_ */
