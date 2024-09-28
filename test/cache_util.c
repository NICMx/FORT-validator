#include "cache_util.h"

#include <check.h>
#include <string.h>
#include "types/uthash.h"

void
ck_assert_cachent_eq(struct cache_node *expected, struct cache_node *actual)
{
	struct cache_node *echild, *achild, *tmp;

	PR_DEBUG_MSG("Comparing %s vs %s", expected->url, actual->url);

	ck_assert_str_eq(expected->url, actual->url);
	ck_assert_str_eq(expected->path, actual->path);
	ck_assert_str_eq(expected->name, actual->name);
	ck_assert_int_eq(expected->flags, actual->flags);
	if (expected->tmppath)
		ck_assert_str_eq(expected->tmppath, actual->tmppath);
	else
		ck_assert_ptr_eq(NULL, actual->tmppath);

	HASH_ITER(hh, expected->children, echild, tmp) {
		HASH_FIND(hh, actual->children, echild->name,
		    strlen(echild->name), achild);
		if (achild == NULL)
			ck_abort_msg("Expected not found: %s", echild->url);
		ck_assert_cachent_eq(echild, achild);
	}

	HASH_ITER(hh, actual->children, achild, tmp) {
		HASH_FIND(hh, expected->children, achild->name,
		    strlen(achild->name), echild);
		if (echild == NULL)
			ck_abort_msg("Actual not found: %s", achild->url);
	}
}

static struct cache_node *
vnode(char const *url, char const *path, int flags, char const *tmppath,
    va_list children)
{
	struct cache_node *result;
	struct cache_node *child;
	char buffer[64];

	result = pzalloc(sizeof(struct cache_node));

	result->url = (char *)url;
	result->path = (char *)path;
	result->name = path_filename(result->path);
	ck_assert_ptr_ne(NULL, result->name);
	result->flags = flags;
	result->tmppath = (char *)tmppath;

	while ((child = va_arg(children, struct cache_node *)) != NULL) {
		HASH_ADD_KEYPTR(hh, result->children, child->name,
		    strlen(child->name), child);
		child->parent = result;
	}

	return result;
}

struct cache_node *
rftnode(char const *url, char const *path, int flags, char const *tmppath, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, tmppath);
	result = vnode(url, path, flags, tmppath, children);
	va_end(children);

	return result;
}

struct cache_node *
rfnode(char const *url, char const *path, int flags, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, flags);
	result = vnode(url, path, flags, NULL, children);
	va_end(children);

	return result;
}

struct cache_node *
rnode(char const *url, char const *path, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, path);
	result = vnode(url, path, 0, NULL, children);
	va_end(children);

	return result;
}

struct cache_node *
hftnode(char const *url, char const *path, int flags, char const *tmppath, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, tmppath);
	result = vnode(url, path, flags, tmppath, children);
	va_end(children);

	return result;
}

struct cache_node *
hfnode(char const *url, char const *path, int flags, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, flags);
	result = vnode(url, path, flags, NULL, children);
	va_end(children);

	return result;
}

struct cache_node *
hnode(char const *url, char const *path, ...)
{
	struct cache_node *result;
	va_list children;

	va_start(children, path);
	result = vnode(url, path, 0, NULL, children);
	va_end(children);

	return result;
}
