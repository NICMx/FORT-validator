#include "cache/common.h"

#include <stdarg.h>
#include <string.h>
#include "data_structure/uthash.h"

struct cache_node *
node(char const *url, int flags, ...)
{
	struct cache_node *result;
	struct cache_node *child;
	char const *slash;
	va_list args;

	result = pzalloc(sizeof(struct cache_node));
	result->url = pstrdup(url);
	slash = strrchr(url, '/');
	result->name = slash ? (slash + 1) : result->url;
	result->flags = flags;

	va_start(args, flags);
	while ((child = va_arg(args, struct cache_node *)) != NULL) {
		HASH_ADD_KEYPTR(hh, result->children, child->name,
		    strlen(child->name), child);
		child->parent = result;
	}
	va_end(args);

	return result;
}
