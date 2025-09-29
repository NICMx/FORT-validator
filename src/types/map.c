#include "types/map.h"

void
map_copy(struct cache_mapping *dst, struct cache_mapping const *src)
{
	uri_copy(&dst->url, &src->url);
	dst->path = pstrdup(src->path);
}

void
map_cleanup(struct cache_mapping *map)
{
	uri_cleanup(&map->url);
	free(map->path);
}
