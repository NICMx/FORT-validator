#include "rrdp/db/db_rrdp.h"

#include <sys/queue.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "crypto/hash.h"
#include "common.h"
#include "log.h"

struct tal_elem {
	char *file_name;
	struct db_rrdp_uri *uris;
	char *workspace;
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

	hash = malloc(HASH_LEN * sizeof(unsigned char));
	if (hash == NULL)
		return pr_enomem();

	hash_len = 0;
	error = hash_str("sha1", base, hash, &hash_len);
	if (error) {
		free(hash);
		return error;
	}

	/* Get the first bytes + one slash + NUL char */
	tmp = malloc(OUT_LEN + 2);
	if (tmp == NULL) {
		free(hash);
		return pr_enomem();
	}

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

static int
tal_elem_create(struct tal_elem **elem, char const *name)
{
	struct tal_elem *tmp;
	struct db_rrdp_uri *tmp_uris;
	int error;

	tmp = malloc(sizeof(struct tal_elem));
	if (tmp == NULL)
		return pr_enomem();

	tmp_uris = NULL;
	error = db_rrdp_uris_create(&tmp_uris);
	if (error)
		goto end1;
	tmp->uris = tmp_uris;

	tmp->visited = true;
	tmp->file_name = strdup(name);
	if (tmp->file_name == NULL) {
		error = pr_enomem();
		goto end2;
	}

	error = get_workspace_path(name, &tmp->workspace);
	if (error)
		goto end3;

	*elem = tmp;
	return 0;
end3:
	free(tmp->file_name);
end2:
	db_rrdp_uris_destroy(tmp->uris);
end1:
	free(tmp);
	return error;
}

static void
tal_elem_destroy(struct tal_elem *elem, bool remove_local)
{
	if (remove_local)
		db_rrdp_uris_remove_all_local(elem->uris, elem->workspace);
	db_rrdp_uris_destroy(elem->uris);
	free(elem->file_name);
	free(elem->workspace);
	free(elem);
}

int
db_rrdp_init(void)
{
	int error;

	error = pthread_rwlock_init(&lock, NULL);
	if (error)
		return pr_op_errno(error, "DB RRDP pthread_rwlock_init() errored");

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

int
db_rrdp_add_tal(char const *tal_name)
{
	struct tal_elem *elem, *found;
	int error;

	/* Element exists, no need to create it again */
	found = db_rrdp_find_tal(tal_name);
	if (found != NULL) {
		found->visited = true;
		return 0;
	}

	error = tal_elem_create(&elem, tal_name);
	if (error)
		return error;

	rwlock_write_lock(&lock);
	SLIST_INSERT_HEAD(&db.tals, elem, next);
	rwlock_unlock(&lock);

	return 0;
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

char const *
db_rrdp_get_workspace(char const *tal_name)
{
	struct tal_elem *found;

	found = db_rrdp_find_tal(tal_name);
	if (found == NULL)
		pr_crit("db_rrdp_find_tal() returned NULL, means it hasn't been initialized");

	return found->workspace;
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
