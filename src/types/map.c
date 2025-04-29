#include "types/map.h"

#include "alloc.h"
#include "config.h"
#include "log.h"
#include "types/path.h"

static char const *
map_get_printable(struct cache_mapping const *map, enum filename_format format)
{
	switch (format) {
	case FNF_GLOBAL:
		return uri_str(&map->url);
	case FNF_LOCAL:
		return map->path;
	case FNF_NAME:
		return path_filename(uri_str(&map->url));
	}

	pr_crit("Unknown file name format: %u", format);
	return NULL;
}

char const *
map_val_get_printable(struct cache_mapping const *map)
{
	return map_get_printable(map, config_get_val_log_file_format());
}

char const *
map_op_get_printable(struct cache_mapping const *map)
{
	return map_get_printable(map, config_get_op_log_file_format());
}

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
