#include "db_rrdp.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "data_structure/uthash_nonfatal.h"
#include "rrdp/rrdp_objects.h"
#include "log.h"

struct db_rrdp_uri {
	/* Key */
	char *uri;
	struct global_data data;
	long last_update;
	UT_hash_handle hh;
};

struct db_rrdp {
	struct db_rrdp_uri *uris;
};

static int
get_current_time(long *result)
{
	time_t now;

	now = time(NULL);
	if (now == ((time_t) -1))
		return pr_errno(errno, "Error getting the current time");

	*result = now;
	return 0;
}

static int
db_rrdp_uri_create(char const *uri, char const *session_id,
    unsigned long serial, struct db_rrdp_uri **result)
{
	struct db_rrdp_uri *tmp;
	int error;

	tmp = malloc(sizeof(struct db_rrdp_uri));
	if (tmp == NULL)
		return pr_enomem();
	/* Needed by uthash */
	memset(tmp, 0, sizeof(struct db_rrdp_uri));

	tmp->uri = strdup(uri);
	if (tmp->uri == NULL) {
		error = pr_enomem();
		goto release_tmp;
	}

	tmp->data.session_id = strdup(session_id);
	if (tmp->data.session_id == NULL) {
		error = pr_enomem();
		goto release_uri;
	}

	tmp->data.serial = serial;
	tmp->last_update = 0;

	*result = tmp;
	return 0;
release_uri:
	free(tmp->uri);
release_tmp:
	free(tmp);
	return error;
}

static void
db_rrdp_uri_destroy(struct db_rrdp_uri *uri)
{
	free(uri->data.session_id);
	free(uri->uri);
	free(uri);
}

static int
add_rrdp_uri(struct db_rrdp *db, struct db_rrdp_uri *new_uri)
{
	struct db_rrdp_uri *old_uri;

	errno = 0;
	HASH_FIND_STR(db->uris, new_uri->uri, old_uri);
	if (errno)
		return pr_errno(errno,
		    "RRDP URI couldn't be added to hash table");

	if (old_uri != NULL) {
		HASH_DELETE(hh, db->uris, old_uri);
		db_rrdp_uri_destroy(old_uri);
	}
	HASH_ADD_KEYPTR(hh, db->uris, new_uri->uri, strlen(new_uri->uri),
	    new_uri);

	return 0;
}

enum rrdp_uri_cmp_result
db_rrdp_cmp_uri(struct db_rrdp *db, char const *uri, char const *session_id,
    unsigned long serial)
{
	struct db_rrdp_uri *found;

	HASH_FIND_STR(db->uris, uri, found);
	if (found == NULL)
		return RRDP_URI_NOTFOUND;

	if (strcmp(session_id, found->data.session_id) != 0)
		return RRDP_URI_DIFF_SESSION;

	if (serial != found->data.serial)
		return RRDP_URI_DIFF_SERIAL;

	return RRDP_URI_EQUAL;
}

int
db_rrdp_add_uri(struct db_rrdp *db, char const *uri, char const *session_id,
    unsigned long serial)
{
	struct db_rrdp_uri *db_uri;
	int error;

	db_uri = NULL;
	error = db_rrdp_uri_create(uri, session_id, serial, &db_uri);
	if (error)
		return error;

	error = add_rrdp_uri(db, db_uri);
	if (error) {
		db_rrdp_uri_destroy(db_uri);
		return error;
	}

	return 0;
}

int
db_rrdp_get_serial(struct db_rrdp *db, char const *uri, unsigned long *serial)
{
	struct db_rrdp_uri *found;

	HASH_FIND_STR(db->uris, uri, found);
	if (found == NULL)
		return -ENOENT;

	*serial = found->data.serial;

	return 0;
}

int
db_rrdp_get_last_update(struct db_rrdp *db, char const *uri, long *date)
{
	struct db_rrdp_uri *found;

	HASH_FIND_STR(db->uris, uri, found);
	if (found == NULL)
		return -ENOENT;

	*date = found->last_update;

	return 0;
}

/* Set the last update to now */
int
db_rrdp_set_last_update(struct db_rrdp *db, char const *uri)
{
	struct db_rrdp_uri *found;

	HASH_FIND_STR(db->uris, uri, found);
	if (found == NULL)
		return -ENOENT;

	return get_current_time(&found->last_update);
}

int
db_rrdp_create(struct db_rrdp **result)
{
	struct db_rrdp *tmp;

	tmp = malloc(sizeof(struct db_rrdp));
	if (tmp == NULL)
		return pr_enomem();

	tmp->uris = NULL;

	*result = tmp;
	return 0;
}

void
db_rddp_destroy(struct db_rrdp *db)
{
	struct db_rrdp_uri *uri_node, *uri_tmp;

	HASH_ITER(hh, db->uris, uri_node, uri_tmp) {
		HASH_DEL(db->uris, uri_node);
		db_rrdp_uri_destroy(uri_node);
	}

	free(db);
}
