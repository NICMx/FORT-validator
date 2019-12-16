#include "visited_uris.h"

#include <sys/queue.h>
#include <stddef.h>
#include <string.h>
#include "log.h"
#include "delete_dir_daemon.h"

/*
 * FIXME (now) This should be replaced with something better (rtrie?)
 */
struct visited_elem {
	char *uri;
	SLIST_ENTRY(visited_elem) next;
};

SLIST_HEAD(visited_list, visited_elem);

struct visited_uris {
	struct visited_list *list;
	unsigned int refs;
};

static int
visited_elem_create(struct visited_elem **elem, char const *uri)
{
	struct visited_elem *tmp;

	tmp = malloc(sizeof(struct visited_elem));
	if (tmp == NULL)
		return pr_enomem();

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
	struct visited_list *tmp_list;

	tmp = malloc(sizeof(struct visited_uris));
	if (tmp == NULL)
		return pr_enomem();

	tmp_list = malloc(sizeof(struct visited_list));
	if (tmp_list == NULL) {
		free(tmp);
		return pr_enomem();
	}

	SLIST_INIT(tmp_list);
	tmp->list = tmp_list;
	tmp->refs = 1;

	*uris = tmp;
	return 0;
}

void
visited_uris_refget(struct visited_uris *uris)
{
	uris->refs++;
}

void
visited_uris_refput(struct visited_uris *uris)
{
	struct visited_elem *elem;

	uris->refs--;
	if (uris->refs == 0) {
		while (!SLIST_EMPTY(uris->list)) {
			elem = uris->list->slh_first;
			SLIST_REMOVE_HEAD(uris->list, next);
			visited_elem_destroy(elem);
		}
		free(uris->list);
		free(uris);
	}
}

static struct visited_elem *
elem_find(struct visited_list *list, char const *uri)
{
	struct visited_elem *found;

	SLIST_FOREACH(found, list, next)
		if (strcmp(uri, found->uri) == 0)
			return found;

	return NULL;
}

int
visited_uris_add(struct visited_uris *uris, char const *uri)
{
	struct visited_elem *elem;
	int error;

	if (elem_find(uris->list, uri) != NULL)
		return 0; /* Exists, don't add again */

	error = visited_elem_create(&elem, uri);
	if (error)
		return error;

	SLIST_INSERT_HEAD(uris->list, elem, next);

	return 0;
}

int
visited_uris_remove(struct visited_uris *uris, char const *uri)
{
	struct visited_elem *elem;

	elem = elem_find(uris->list, uri);
	if (elem == NULL)
		return pr_err("Trying to remove a nonexistent URI '%s'", uri);

	SLIST_REMOVE(uris->list, elem, visited_elem, next);
	visited_elem_destroy(elem);

	return 0;
}

bool
visited_uris_exists(struct visited_uris *uris, char const *uri)
{
	return elem_find(uris->list, uri) != NULL;
}

int
visited_uris_get_root(struct visited_uris *uris, char **result)
{
	struct visited_elem *elem;
	char *tmp, *ptr;
	size_t size;
	int i;

	elem = SLIST_FIRST(uris->list);

	/* No elements yet */
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
	tmp[size + 1] = '\0';

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
