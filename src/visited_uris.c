#include "visited_uris.h"

#include <sys/queue.h>
#include <stddef.h>
#include <string.h>
#include "alloc.h"
#include "log.h"
#include "delete_dir_daemon.h"
#include "data_structure/array_list.h"
#include "data_structure/uthash.h"

struct visited_elem {
	/* key */
	char *uri;
	UT_hash_handle hh;
};

struct visited_uris {
	struct visited_elem *table;
	unsigned int refs;
};

DEFINE_ARRAY_LIST_STRUCT(uris_roots, char *);
DEFINE_ARRAY_LIST_FUNCTIONS(uris_roots, char *, static)

static struct visited_elem *
visited_elem_create(char const *uri)
{
	struct visited_elem *tmp;

	tmp = pzalloc(sizeof(struct visited_elem)); /* Zero needed by uthash */
	tmp->uri = pstrdup(uri);

	return tmp;
}

static void
visited_elem_destroy(struct visited_elem *elem)
{
	free(elem->uri);
	free(elem);
}

struct visited_uris *
visited_uris_create(void)
{
	struct visited_uris *tmp;

	tmp = pmalloc(sizeof(struct visited_uris));

	tmp->table = NULL;
	tmp->refs = 1;

	return tmp;
}

static void
visited_uris_destroy(struct visited_uris *uris)
{
	struct visited_elem *elm_node, *elm_tmp;

	HASH_ITER(hh, uris->table, elm_node, elm_tmp) {
		HASH_DEL(uris->table, elm_node);
		visited_elem_destroy(elm_node);
	}
	free(uris);
}

void
visited_uris_refget(struct visited_uris *uris)
{
	uris->refs++;
}

void
visited_uris_refput(struct visited_uris *uris)
{
	uris->refs--;
	if (uris->refs == 0)
		visited_uris_destroy(uris);
}

static struct visited_elem *
elem_find(struct visited_uris *list, char const *uri)
{
	struct visited_elem *found;
	HASH_FIND_STR(list->table, uri, found);
	return found;
}

void
visited_uris_add(struct visited_uris *uris, char const *uri)
{
	struct visited_elem *node;

	if (elem_find(uris, uri) == NULL) {
		/* Do not inline; HASH_ADD_STR expands "add" multiple times. */
		node = visited_elem_create(uri);
		HASH_ADD_STR(uris->table, uri, node);
	}
}

int
visited_uris_remove(struct visited_uris *uris, char const *uri)
{
	struct visited_elem *elem;

	elem = elem_find(uris, uri);
	if (elem == NULL)
		return pr_val_err("Trying to remove a nonexistent URI '%s'", uri);

	HASH_DEL(uris->table, elem);
	visited_elem_destroy(elem);

	return 0;
}

static void
visited_uris_to_arr(struct visited_uris *uris, struct uris_roots *roots)
{
	struct visited_elem *elem;
	char *tmp, *last_slash;
	size_t size;

	for (elem = uris->table; elem != NULL; elem = elem->hh.next) {
		last_slash = strrchr(elem->uri, '/');
		size = last_slash - elem->uri;
		tmp = pmalloc(size + 1);
		strncpy(tmp, elem->uri, size);
		tmp[size] = '\0';
		uris_roots_add(roots, &tmp);
	}
}

static void
uris_root_destroy(char **elem)
{
	free(*elem);
}

/*
 * Delete all the corresponding local files of @uris located at @workspace
 */
int
visited_uris_delete_local(struct visited_uris *uris)
{
	struct uris_roots roots;
	int error;

	uris_roots_init(&roots);
	visited_uris_to_arr(uris, &roots);
	if (roots.len == 0)
		goto success;

	error = delete_dir_daemon_start(roots.array, roots.len);
	if (error) {
		uris_roots_cleanup(&roots, uris_root_destroy);
		return error;
	}

success:
	uris_roots_cleanup(&roots, uris_root_destroy);
	return 0;
}
