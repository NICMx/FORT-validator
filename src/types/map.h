#ifndef SRC_TYPES_MAP_H_
#define SRC_TYPES_MAP_H_

#include "asn1/asn1c/IA5String.h"
#include "data_structure/array_list.h"

/*
 * "Long" time = seven days.
 * Currently hardcoded, but queued for tweakability.
 */
enum map_type {
	/*
	 * (rsync) Repository Publication Point. RFC 6481.
	 * The directory is cached until it's untraversed for a "long" time.
	 */
	MAP_RSYNC = (1 << 0),

	MAP_HTTP = (1 << 1),

	/*
	 * An RRDP notification file; downloaded via HTTP.
	 * The file itself is not cached, but we preserve a handful of metadata
	 * that is needed in subsequent iterations.
	 * The metadata is cached until it's untraversed for a "long" time.
	 */
	MAP_NOTIF = (MAP_HTTP | (1 << 2)),
};

struct cache_mapping;

struct cache_mapping *create_map(char const *);

struct cache_mapping *map_refget(struct cache_mapping *);
void map_refput(struct cache_mapping *);

/*
 * Note that, if you intend to print some mapping, you're likely supposed to use
 * map_*_get_printable() instead.
 */
char const *map_get_url(struct cache_mapping *);
char const *map_get_path(struct cache_mapping *);

bool map_has_extension(struct cache_mapping *, char const *);

enum map_type map_get_type(struct cache_mapping *);

char const *map_val_get_printable(struct cache_mapping *);
char const *map_op_get_printable(struct cache_mapping *);

/* Plural */

/* XXX still used? */
DEFINE_ARRAY_LIST_STRUCT(map_list, struct cache_mapping *);

void maps_init(struct map_list *);
void maps_cleanup(struct map_list *);

void maps_add(struct map_list *, struct cache_mapping *);

#endif /* SRC_TYPES_MAP_H_ */
