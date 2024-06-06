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
	 * TAL's TA URL.
	 * The file is cached until it's untraversed for a "long" time.
	 */
	MAP_TA_RSYNC,
	MAP_TA_HTTP,

	/*
	 * (rsync) Repository Publication Point. RFC 6481.
	 * The directory is cached until it's untraversed for a "long" time.
	 */
	MAP_RPP,

	/*
	 * An RRDP notification file; downloaded via HTTP.
	 * The file itself is not cached, but we preserve a handful of metadata
	 * that is needed in subsequent iterations.
	 * The metadata is cached until it's untraversed for a "long" time.
	 */
	MAP_NOTIF,

	/*
	 * RRDP Snapshot or Delta; downloaded via HTTP.
	 * The file itself is not cached, but we preserve some small metadata.
	 * The metadata is destroyed once the iteration finishes.
	 */
	MAP_TMP,

	/*
	 * Endangered species; bound to be removed once RFC 9286 is implemented.
	 */
	MAP_CAGED,

	MAP_AIA, /* caIssuers. Not directly downloaded. */
	MAP_SO, /* signedObject. Not directly downloaded. */
	MAP_MFT, /* rpkiManifest. Not directly downloaded. */
};

struct cache_mapping;

int map_create(struct cache_mapping **, enum map_type, struct cache_mapping *,
	       char const *);
int map_create_mft(struct cache_mapping **, struct cache_mapping *, struct cache_mapping *,
		   IA5String_t *);
struct cache_mapping *map_create_cache(char const *);

#define map_create_caged(map, notif, url) \
	map_create(map, MAP_CAGED, notif, url)
#define map_create_cage(map, notif) \
	map_create_caged(map, notif, NULL)

struct cache_mapping *map_refget(struct cache_mapping *);
void map_refput(struct cache_mapping *);

/*
 * Note that, if you intend to print some mapping, you're likely supposed to use
 * map_get_printable() instead.
 */
char const *map_get_url(struct cache_mapping *);
char const *map_get_path(struct cache_mapping *);

bool map_equals(struct cache_mapping *, struct cache_mapping *);
bool str_same_origin(char const *, char const *);
bool map_same_origin(struct cache_mapping *, struct cache_mapping *);
bool map_has_extension(struct cache_mapping *, char const *);
bool map_is_certificate(struct cache_mapping *);

enum map_type map_get_type(struct cache_mapping *);

char const *map_val_get_printable(struct cache_mapping *);
char const *map_op_get_printable(struct cache_mapping *);

char *map_get_rrdp_workspace(struct cache_mapping *);

/* Plural */

DEFINE_ARRAY_LIST_STRUCT(map_list, struct cache_mapping *);

void maps_init(struct map_list *);
void maps_cleanup(struct map_list *);

void maps_add(struct map_list *, struct cache_mapping *);

#endif /* SRC_TYPES_MAP_H_ */
