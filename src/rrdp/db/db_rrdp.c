#include "rrdp/db/db_rrdp.h"

#include <sys/queue.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "alloc.h"
#include "crypto/hash.h"
#include "common.h"
#include "log.h"

struct tal_elem {
	char *file_name;
	struct db_rrdp_uri *uris;
	bool visited;
	SLIST_ENTRY(tal_elem) next;
};

SLIST_HEAD(tal_list, tal_elem);

struct db_rrdp {
	struct tal_list tals;
};

static struct db_rrdp db;

/** Read/write lock, which protects @db. */
static pthread_rwlock_t lock;

/*
 * Creates an ID for the RRDP local workspace.
 *
 * The ID is generated using the hash (sha-1) of @base. The first 4 bytes of
 * the hash are "stringified" (8 chars) and a '/' is added at the end to
 * (later) facilitate the concatenation of the ID at --local-repository.
 * 
 * The ID is allocated at @result.
 *
 * TODO (#78) Improve and use this.
 */
static int
get_workspace_path(char const *base, char **result)
{
/* SHA1 produces 20 bytes */
#define HASH_LEN 20
/* We'll use the first 4 bytes (8 chars) */
#define OUT_LEN   8
	unsigned char *hash;
	unsigned int hash_len;
	unsigned int i;
	char *tmp;
	char *ptr;
	int error;

	hash = pmalloc(HASH_LEN * sizeof(unsigned char));

	hash_len = 0;
	error = hash_str("sha1", base, hash, &hash_len);
	if (error) {
		free(hash);
		return error;
	}

	/* Get the first bytes + one slash + NUL char */
	tmp = pmalloc(OUT_LEN + 2);

	ptr = tmp;
	for (i = 0; i < OUT_LEN / 2; i++) {
		sprintf(ptr, "%02X", hash[i]);
		ptr += 2;
	}
	tmp[OUT_LEN] = '/';
	tmp[OUT_LEN + 1] = '\0';

	free(hash);
	*result = tmp;
	return 0;
}

static struct tal_elem *
tal_elem_create(char const *name)
{
	struct tal_elem *result;

	result = pmalloc(sizeof(struct tal_elem));

	result->uris = db_rrdp_uris_create();
	result->visited = true;
	result->file_name = pstrdup(name);

	return result;
}

static void
tal_elem_destroy(struct tal_elem *elem, bool remove_local)
{
	db_rrdp_uris_destroy(elem->uris);
	free(elem->file_name);
	free(elem);
}

int
db_rrdp_init(void)
{
	int error;

	error = pthread_rwlock_init(&lock, NULL);
	if (error) {
		pr_op_err("DB RRDP pthread_rwlock_init() errored: %s",
		    strerror(error));
		return error;
	}

	SLIST_INIT(&db.tals);
	return 0;
}

void
db_rrdp_cleanup(void)
{
	struct tal_elem *elem;

	while (!SLIST_EMPTY(&db.tals)) {
		elem = db.tals.slh_first;
		SLIST_REMOVE_HEAD(&db.tals, next);
		tal_elem_destroy(elem, false);
	}
	pthread_rwlock_destroy(&lock);
}

static struct tal_elem *
db_rrdp_find_tal(char const *tal_name)
{
	struct tal_elem *found;

	rwlock_read_lock(&lock);
	SLIST_FOREACH(found, &db.tals, next) {
		if (strcmp(tal_name, found->file_name) == 0) {
			rwlock_unlock(&lock);
			return found;
		}
	}
	rwlock_unlock(&lock);

	return NULL;
}

void
db_rrdp_add_tal(char const *tal_name)
{
	struct tal_elem *elem, *found;

	/* Element exists, no need to create it again */
	found = db_rrdp_find_tal(tal_name);
	if (found != NULL) {
		found->visited = true;
		return;
	}

	elem = tal_elem_create(tal_name);

	rwlock_write_lock(&lock);
	SLIST_INSERT_HEAD(&db.tals, elem, next);
	rwlock_unlock(&lock);
}

void
db_rrdp_rem_tal(char const *tal_name)
{
	struct tal_elem *found;

	found = db_rrdp_find_tal(tal_name);
	if (found == NULL)
		return;

	rwlock_write_lock(&lock);
	SLIST_REMOVE(&db.tals, found, tal_elem, next);
	rwlock_unlock(&lock);

	tal_elem_destroy(found, true);
}

/* Returns the reference to RRDP URIs of a TAL */
struct db_rrdp_uri *
db_rrdp_get_uris(char const *tal_name)
{
	struct tal_elem *found;

	found = db_rrdp_find_tal(tal_name);
	if (found == NULL)
		pr_crit("db_rrdp_find_tal() returned NULL, means it hasn't been initialized");

	return found->uris;
}

/* Set all tals to non-visited */
void
db_rrdp_reset_visited_tals(void)
{
	struct tal_elem *found;

	rwlock_write_lock(&lock);
	SLIST_FOREACH(found, &db.tals, next)
		found->visited = false;
	rwlock_unlock(&lock);
}

/* Remove non-visited tals */
void
db_rrdp_rem_nonvisited_tals(void)
{
	struct tal_elem *found;

	rwlock_write_lock(&lock);
	SLIST_FOREACH(found, &db.tals, next) {
		if (!found->visited) {
			SLIST_REMOVE(&db.tals, found, tal_elem, next);
			tal_elem_destroy(found, true);
		}
	}
	rwlock_unlock(&lock);
}
