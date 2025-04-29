#ifndef SRC_TYPES_MAP_H_
#define SRC_TYPES_MAP_H_

#include "types/url.h"

// XXX document this better
struct cache_mapping {
	struct uri url;		/* Normalized */
	char *path;		/* Normalized */
};

char const *map_val_get_printable(struct cache_mapping const *);
char const *map_op_get_printable(struct cache_mapping const *);

void map_copy(struct cache_mapping *, struct cache_mapping const *);
void map_cleanup(struct cache_mapping *);

#endif /* SRC_TYPES_MAP_H_ */
