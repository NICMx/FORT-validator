#include "visited_uris.h"

#include <sys/queue.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>
#include "common.h"
#include "log.h"

/*
 * FIXME (now) This should be replaced with something better (rtrie?)
 */
struct visited_elem {
	char *uri;
	SLIST_ENTRY(visited_elem) next;
};

SLIST_HEAD(visited_uris, visited_elem) uris_db;

/** Read/write lock, which protects @uris_db. */
static pthread_rwlock_t lock;

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
visited_uris_init(void)
{
	int error;

	error = pthread_rwlock_init(&lock, NULL);
	if (error)
		return pr_errno(error, "Visited uris pthread_rwlock_init() errored");

	SLIST_INIT(&uris_db);
	return 0;
}

void
visited_uris_destroy(void)
{
	struct visited_elem *elem;

	while (!SLIST_EMPTY(&uris_db)) {
		elem = uris_db.slh_first;
		SLIST_REMOVE_HEAD(&uris_db, next);
		visited_elem_destroy(elem);
	}
	pthread_rwlock_destroy(&lock);
}

static struct visited_elem *
elem_find(struct visited_uris *list, char const *uri)
{
	struct visited_elem *found;

	rwlock_read_lock(&lock);
	SLIST_FOREACH(found, list, next) {
		if (strcmp(uri, found->uri) == 0) {
			rwlock_unlock(&lock);
			return found;
		}
	}
	rwlock_unlock(&lock);
	return NULL;
}

int
visited_uris_add(char const *uri)
{
	struct visited_elem *elem;
	int error;

	if (elem_find(&uris_db, uri) != NULL)
		return 0; /* Exists, don't add again */

	error = visited_elem_create(&elem, uri);
	if (error)
		return error;

	rwlock_write_lock(&lock);
	SLIST_INSERT_HEAD(&uris_db, elem, next);
	rwlock_unlock(&lock);

	return 0;
}

int
visited_uris_remove(char const *uri)
{
	struct visited_elem *elem;

	elem = elem_find(&uris_db, uri);
	if (elem == NULL)
		return pr_err("Trying to remove a nonexistent URI '%s'", uri);

	rwlock_write_lock(&lock);
	SLIST_REMOVE(&uris_db, elem, visited_elem, next);
	visited_elem_destroy(elem);
	rwlock_unlock(&lock);

	return 0;
}

bool
visited_uris_exists(char const *uri)
{
	return elem_find(&uris_db, uri) != NULL;
}
