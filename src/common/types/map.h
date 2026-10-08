#ifndef COMMON_TYPES_MAP_H_
#define COMMON_TYPES_MAP_H_

#include "common/types/uri.h"

struct cache_mapping {
	/* Global identifier of a file */
	struct uri url;
	/* Cache location where the file was (or will be) downloaded */
	char *path;
};

void map_copy(struct cache_mapping *, struct cache_mapping const *);
void map_cleanup(struct cache_mapping *);

#endif /* COMMON_TYPES_MAP_H_ */
