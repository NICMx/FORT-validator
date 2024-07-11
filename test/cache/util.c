#include "cache/util.h"

#include <string.h>
#include "data_structure/uthash.h"

struct cache_node *
vnode(char const *url, int flags, char const *tmpdir, va_list children)
{
	struct cache_node *result;
	struct cache_node *child;
	char const *slash;

	result = pzalloc(sizeof(struct cache_node));
	result->url = pstrdup(url);
	slash = strrchr(url, '/');
	result->name = slash ? (slash + 1) : result->url;
	result->flags = flags;
	result->tmpdir = tmpdir ? pstrdup(tmpdir) : NULL;

	while ((child = va_arg(children, struct cache_node *)) != NULL) {
		HASH_ADD_KEYPTR(hh, result->children, child->name,
		    strlen(child->name), child);
		child->parent = result;
	}

	return result;
}

struct cache_node *
uftnode(char const *url, int flags, char const *tmpdir, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, tmpdir);
	result = vnode(url, flags, tmpdir, children);
	va_end(children);

	return result;
}

struct cache_node *
ufnode(char const *url, int flags, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, flags);
	result = vnode(url, flags, NULL, children);
	va_end(children);

	return result;
}

struct cache_node *
unode(char const *url, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, url);
	result = vnode(url, 0, NULL, children);
	va_end(children);

	return result;
}
