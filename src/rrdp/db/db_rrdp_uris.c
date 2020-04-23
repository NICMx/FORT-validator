#include "rrdp/db/db_rrdp_uris.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "data_structure/uthash_nonfatal.h"
#include "log.h"
#include "thread_var.h"
#include "visited_uris.h"

struct uris_table {
	/* Key */
	char *uri;
	/* Last session ID and serial from the URI */
	struct global_data data;
	/* Last local update of the URI (after a successful processing) */
	long last_update;
	/* The URI has been requested (HTTPS) at this cycle? */
	rrdp_req_status_t request_status;
	/* MFT URIs loaded from the @uri */
	struct visited_uris *visited_uris;
	UT_hash_handle hh;
};

struct db_rrdp_uri {
	struct uris_table *table;
};

static int
uris_table_create(char const *uri, char const *session_id,
    unsigned long serial, rrdp_req_status_t req_status,
    struct uris_table **result)
{
	struct uris_table *tmp;
	int error;

	tmp = malloc(sizeof(struct uris_table));
	if (tmp == NULL)
		return pr_enomem();
	/* Needed by uthash */
	memset(tmp, 0, sizeof(struct uris_table));

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
	tmp->request_status = req_status;
	tmp->visited_uris = NULL;

	*result = tmp;
	return 0;
release_uri:
	free(tmp->uri);
release_tmp:
	free(tmp);
	return error;
}

static void
uris_table_destroy(struct uris_table *uri)
{
	visited_uris_refput(uri->visited_uris);
	free(uri->data.session_id);
	free(uri->uri);
	free(uri);
}

static struct uris_table *
find_rrdp_uri(struct db_rrdp_uri *uris, const char *search)
{
	struct uris_table *found;
	HASH_FIND_STR(uris->table, search, found);
	return found;
}

#define RET_NOT_FOUND_URI(uris, search, found)				\
	found = find_rrdp_uri(uris, search);				\
	if (found == NULL)						\
		return -ENOENT;

static void
add_rrdp_uri(struct db_rrdp_uri *uris, struct uris_table *new_uri)
{
	struct uris_table *old_uri;

	old_uri = find_rrdp_uri(uris, new_uri->uri);
	if (old_uri != NULL) {
		HASH_DELETE(hh, uris->table, old_uri);
		uris_table_destroy(old_uri);
	}
	HASH_ADD_KEYPTR(hh, uris->table, new_uri->uri, strlen(new_uri->uri),
	    new_uri);
}

static int
get_thread_rrdp_uris(struct db_rrdp_uri **result)
{
	struct validation *state;

	state = state_retrieve();
	if (state == NULL)
		return pr_err("No state related to this thread");

	*result = validation_get_rrdp_uris(state);
	return 0;
}

int
db_rrdp_uris_create(struct db_rrdp_uri **uris)
{
	struct db_rrdp_uri *tmp;

	tmp = malloc(sizeof(struct db_rrdp_uri));
	if (tmp == NULL)
		return pr_enomem();

	tmp->table = NULL;

	*uris = tmp;
	return 0;
}

void
db_rrdp_uris_destroy(struct db_rrdp_uri *uris)
{
	struct uris_table *uri_node, *uri_tmp;

	HASH_ITER(hh, uris->table, uri_node, uri_tmp) {
		HASH_DEL(uris->table, uri_node);
		uris_table_destroy(uri_node);
	}
	free(uris);
}

int
db_rrdp_uris_cmp(char const *uri, char const *session_id, unsigned long serial,
    rrdp_uri_cmp_result_t *result)
{
	struct db_rrdp_uri *uris;
	struct uris_table *found;
	int error;

	uris = NULL;
	error = get_thread_rrdp_uris(&uris);
	if (error)
		return error;

	found = find_rrdp_uri(uris, uri);
	if (found == NULL) {
		*result = RRDP_URI_NOTFOUND;
		return 0;
	}

	if (strcmp(session_id, found->data.session_id) != 0) {
		*result = RRDP_URI_DIFF_SESSION;
		return 0;
	}

	if (serial != found->data.serial) {
		*result = RRDP_URI_DIFF_SERIAL;
		return 0;
	}

	*result = RRDP_URI_EQUAL;
	return 0;
}

int
db_rrdp_uris_update(char const *uri, char const *session_id,
    unsigned long serial, rrdp_req_status_t req_status,
    struct visited_uris *visited_uris)
{
	struct db_rrdp_uri *uris;
	struct uris_table *db_uri;
	int error;

	uris = NULL;
	error = get_thread_rrdp_uris(&uris);
	if (error)
		return error;

	db_uri = NULL;
	error = uris_table_create(uri, session_id, serial, req_status, &db_uri);
	if (error)
		return error;

	/* Ownership transfered */
	db_uri->visited_uris = visited_uris;

	add_rrdp_uri(uris, db_uri);

	return 0;
}

int
db_rrdp_uris_get_serial(char const *uri, unsigned long *serial)
{
	struct db_rrdp_uri *uris;
	struct uris_table *found;
	int error;

	uris = NULL;
	error = get_thread_rrdp_uris(&uris);
	if (error)
		return error;

	RET_NOT_FOUND_URI(uris, uri, found)
	*serial = found->data.serial;
	return 0;
}

int
db_rrdp_uris_get_last_update(char const *uri, long *date)
{
	struct db_rrdp_uri *uris;
	struct uris_table *found;
	int error;

	uris = NULL;
	error = get_thread_rrdp_uris(&uris);
	if (error)
		return error;

	RET_NOT_FOUND_URI(uris, uri, found)
	*date = found->last_update;
	return 0;
}

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

/* Set the last update to now */
int
db_rrdp_uris_set_last_update(char const *uri)
{
	struct db_rrdp_uri *uris;
	struct uris_table *found;
	int error;

	uris = NULL;
	error = get_thread_rrdp_uris(&uris);
	if (error)
		return error;

	RET_NOT_FOUND_URI(uris, uri, found)
	return get_current_time(&found->last_update);
}

int
db_rrdp_uris_get_request_status(char const *uri, rrdp_req_status_t *result)
{
	struct db_rrdp_uri *uris;
	struct uris_table *found;
	int error;

	uris = NULL;
	error = get_thread_rrdp_uris(&uris);
	if (error)
		return error;

	RET_NOT_FOUND_URI(uris, uri, found)
	*result = found->request_status;
	return 0;
}

int
db_rrdp_uris_set_request_status(char const *uri, rrdp_req_status_t value)
{
	struct db_rrdp_uri *uris;
	struct uris_table *found;
	int error;

	uris = NULL;
	error = get_thread_rrdp_uris(&uris);
	if (error)
		return error;

	RET_NOT_FOUND_URI(uris, uri, found)
	found->request_status = value;
	return 0;
}

int
db_rrdp_uris_set_all_unvisited(void)
{
	struct db_rrdp_uri *uris;
	struct uris_table *uri_node, *uri_tmp;
	int error;

	uris = NULL;
	error = get_thread_rrdp_uris(&uris);
	if (error)
		return error;

	HASH_ITER(hh, uris->table, uri_node, uri_tmp)
		uri_node->request_status = RRDP_URI_REQ_UNVISITED;

	return 0;
}

/*
 * Returns a pointer (set in @result) to the visited_uris of the current
 * thread.
 */
int
db_rrdp_uris_get_visited_uris(char const *uri, struct visited_uris **result)
{
	struct db_rrdp_uri *uris;
	struct uris_table *found;
	int error;

	uris = NULL;
	error = get_thread_rrdp_uris(&uris);
	if (error)
		return error;

	RET_NOT_FOUND_URI(uris, uri, found)
	*result = found->visited_uris;
	return 0;
}

int
db_rrdp_uris_remove_all_local(struct db_rrdp_uri *uris)
{
	struct uris_table *uri_node, *uri_tmp;
	int error;

	/* Remove each 'visited_uris' from all the table */
	HASH_ITER(hh, uris->table, uri_node, uri_tmp) {
		error = visited_uris_delete_local(uri_node->visited_uris);
		if (error)
			return error;
	}

	return 0;
}
