#include "cache_util.h"

#include <string.h>
#include "types/uthash.h"

static struct cache_node *
node(char const *schema, char const *path, int flags, char const *tmpdir,
    va_list children)
{
	struct cache_node *result;
	struct cache_node *child;
	char buffer[64];
	char const *slash;

	result = pzalloc(sizeof(struct cache_node));

	ck_assert(snprintf(buffer, 64, "%s://%s", schema, path) < 64);
	result->url = pstrdup(buffer);
	slash = (path[0] == 0) ? "" : "/";
	ck_assert(snprintf(buffer, 64, "tmp/%s%s%s", schema, slash, path) < 64);
	result->path = pstrdup(buffer);

	result->name = strrchr(result->path, '/') + 1;
	ck_assert_ptr_ne(NULL, result->name);
	result->flags = flags;
	result->tmppath = tmpdir ? pstrdup(tmpdir) : NULL;

	while ((child = va_arg(children, struct cache_node *)) != NULL) {
		HASH_ADD_KEYPTR(hh, result->children, child->name,
		    strlen(child->name), child);
		child->parent = result;
	}

	return result;
}

struct cache_node *
ruftnode(char const *path, int flags, char const *tmpdir, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, tmpdir);
	result = node("rsync", path, flags, tmpdir, children);
	va_end(children);

	return result;
}

struct cache_node *
rufnode(char const *path, int flags, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, flags);
	result = node("rsync", path, flags, NULL, children);
	va_end(children);

	return result;
}

struct cache_node *
runode(char const *path, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, path);
	result = node("rsync", path, 0, NULL, children);
	va_end(children);

	return result;
}

struct cache_node *
huftnode(char const *path, int flags, char const *tmpdir, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, tmpdir);
	result = node("https", path, flags, tmpdir, children);
	va_end(children);

	return result;
}

struct cache_node *
hufnode(char const *path, int flags, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, flags);
	result = node("https", path, flags, NULL, children);
	va_end(children);

	return result;
}

struct cache_node *
hunode(char const *path, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, path);
	result = node("https", path, 0, NULL, children);
	va_end(children);

	return result;
}
