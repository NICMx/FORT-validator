#include "types/map.h"

#include "alloc.h"
#include "config.h"
#include "log.h"
#include "types/path.h"

static char const *
map_get_printable(struct cache_mapping *map, enum filename_format format)
{
	switch (format) {
	case FNF_GLOBAL:
		return map->url;
	case FNF_LOCAL:
		return map->path;
	case FNF_NAME:
		return path_filename(map->url);
	}

	pr_crit("Unknown file name format: %u", format);
	return NULL;
}

char const *
map_val_get_printable(struct cache_mapping *map)
{
	return map_get_printable(map, config_get_val_log_file_format());
}

char const *
map_op_get_printable(struct cache_mapping *map)
{
	return map_get_printable(map, config_get_op_log_file_format());
}

void
map_parent(struct cache_mapping *child, struct cache_mapping *parent)
{
	parent->url = path_parent(child->url);
	parent->path = path_parent(child->path);
}

struct cache_mapping *
map_child(struct cache_mapping *parent, char const *name)
{
	struct cache_mapping *child;

	child = pmalloc(sizeof(struct cache_mapping));
	child->url = join_paths(parent->url, name);
	child->path = join_paths(parent->path, name);

	return child;
}

void
map_copy(struct cache_mapping *dst, struct cache_mapping *src)
{
	dst->url = pstrdup(src->url);
	dst->path = pstrdup(src->path);
}

void
map_cleanup(struct cache_mapping *map)
{
	free(map->url);
	free(map->path);
}
