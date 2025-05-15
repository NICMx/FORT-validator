#ifndef SRC_TYPES_MAP_H_
#define SRC_TYPES_MAP_H_

#include "types/uri.h"

struct cache_mapping {
	/* Global identifier of a file */
	struct uri url;
	/* Cache location where the file was (or will be) downloaded */
	char *path;
};

char const *map_val_get_printable(struct cache_mapping const *);
char const *map_op_get_printable(struct cache_mapping const *);

void map_copy(struct cache_mapping *, struct cache_mapping const *);
void map_cleanup(struct cache_mapping *);

#endif /* SRC_TYPES_MAP_H_ */
