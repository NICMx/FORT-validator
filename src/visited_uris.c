#include "visited_uris.h"

#include <sys/queue.h>
#include <stddef.h>
#include <string.h>
#include "log.h"
#include "delete_dir_daemon.h"
#include "data_structure/uthash_nonfatal.h"

struct visited_elem {
	/* key */
	char *uri;
	UT_hash_handle hh;
};

struct visited_uris {
	struct visited_elem *table;
	unsigned int refs;
};

static int
visited_elem_create(struct visited_elem **elem, char const *uri)
{
	struct visited_elem *tmp;

	tmp = malloc(sizeof(struct visited_elem));
	if (tmp == NULL)
		return pr_enomem();
	/* Needed by uthash */
	memset(tmp, 0, sizeof(struct visited_elem));

	tmp->uri = strdup(uri);
	if (tmp->uri == NULL) {
		free(tmp);
		return pr_enomem();
	}

	*elem = tmp;
	return 0;
}

static void
visited_elem_destroy(struct visited_elem *elem)
{
	free(elem->uri);
	free(elem);
}

int
visited_uris_create(struct visited_uris **uris)
{
	struct visited_uris *tmp;

	tmp = malloc(sizeof(struct visited_uris));
	if (tmp == NULL)
		return pr_enomem();

	tmp->table = NULL;
	tmp->refs = 1;

	*uris = tmp;
	return 0;
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

int
visited_uris_add(struct visited_uris *uris, char const *uri)
{
	struct visited_elem *elem;
	int error;

	if (elem_find(uris, uri) != NULL)
		return 0; /* Exists, don't add again */

	elem = NULL;
	error = visited_elem_create(&elem, uri);
	if (error)
		return error;

	HASH_ADD_KEYPTR(hh, uris->table, elem->uri, strlen(elem->uri),
	    elem);

	return 0;
}

int
visited_uris_remove(struct visited_uris *uris, char const *uri)
{
	struct visited_elem *elem;

	elem = elem_find(uris, uri);
	if (elem == NULL)
		return pr_err("Trying to remove a nonexistent URI '%s'", uri);

	HASH_DEL(uris->table, elem);
	visited_elem_destroy(elem);

	return 0;
}

bool
visited_uris_exists(struct visited_uris *uris, char const *uri)
{
	return elem_find(uris, uri) != NULL;
}

int
visited_uris_get_root(struct visited_uris *uris, char **result)
{
	struct visited_elem *elem;
	char *tmp, *ptr;
	size_t size;
	int i;

	elem = uris->table;
	if (elem == NULL) {
		*result = NULL;
		return 0;
	}

	i = 0;
	ptr = strchr(elem->uri, '/');
	while(i < 2) {
		ptr = strchr(ptr + 1, '/');
		i++;
	}
	size = ptr - elem->uri;
	tmp = malloc(size + 1);
	if (tmp == NULL)
		return pr_enomem();

	strncpy(tmp, elem->uri, size);
	tmp[size] = '\0';

	*result = tmp;
	return 0;
}

int
visited_uris_remove_local(struct visited_uris *uris)
{
	char *root_path;
	int error;

	error = visited_uris_get_root(uris, &root_path);
	if (error)
		return error;

	if (root_path == NULL)
		return 0;

	error = delete_dir_daemon_start(root_path);
	if (error) {
		free(root_path);
		return error;
	}

	free(root_path);
	return 0;
}
