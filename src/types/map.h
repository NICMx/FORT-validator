#ifndef SRC_TYPES_MAP_H_
#define SRC_TYPES_MAP_H_

// XXX document this better
struct cache_mapping {
	/* Normalized, ASCII-only, NULL-terminated. */
	char *url;
	/* Normalized, ASCII-only, NULL-terminated. */
	char *path;
};

char const *map_val_get_printable(struct cache_mapping *);
char const *map_op_get_printable(struct cache_mapping *);

void map_parent(struct cache_mapping *, struct cache_mapping *);
struct cache_mapping *map_child(struct cache_mapping *, char const *);

void map_copy(struct cache_mapping *, struct cache_mapping *);
void map_cleanup(struct cache_mapping *);

#endif /* SRC_TYPES_MAP_H_ */
