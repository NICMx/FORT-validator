#ifndef SRC_TYPES_MAP_H_
#define SRC_TYPES_MAP_H_

// XXX document this better
struct cache_mapping {
	/*
	 * The one that always starts with "rsync://" or "https://".
	 * Normalized, ASCII-only, NULL-terminated.
	 */
	char const *url;

	/*
	 * Official cache location of the file.
	 * Normalized, ASCII-only, NULL-terminated.
	 */
	char const *path;

	/*
	 * Temporary cache location of the file.
	 * It'll stay here until committed.
	 */
	char const *tmppath;
};

char const *map_val_get_printable(struct cache_mapping *);
char const *map_op_get_printable(struct cache_mapping *);

#endif /* SRC_TYPES_MAP_H_ */
