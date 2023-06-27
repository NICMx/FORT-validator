#include "rrdp/db/db_rrdp_uris.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "data_structure/uthash.h"
#include "alloc.h"
#include "common.h"
#include "log.h"
#include "thread_var.h"

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

static struct uris_table *
uris_table_create(char const *uri, char const *session_id,
    unsigned long serial, rrdp_req_status_t req_status)
{
	struct uris_table *tmp;

	tmp = pzalloc(sizeof(struct uris_table)); /* Zero needed by uthash */

	tmp->uri = pstrdup(uri);
	tmp->data.session_id = pstrdup(session_id);
	tmp->data.serial = serial;
	tmp->last_update = 0;
	tmp->request_status = req_status;
	tmp->visited_uris = NULL;

	return tmp;
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

static void
add_rrdp_uri(struct db_rrdp_uri *uris, struct uris_table *new_uri)
{
	struct uris_table *old_uri;

	HASH_REPLACE_STR(uris->table, uri, new_uri, old_uri);
	if (old_uri != NULL)
		uris_table_destroy(old_uri);
}

static struct db_rrdp_uri *
get_thread_rrdp_uris(void)
{
	return validation_get_rrdp_uris(state_retrieve());
}

struct db_rrdp_uri *
db_rrdp_uris_create(void)
{
	struct db_rrdp_uri *tmp;

	tmp = pmalloc(sizeof(struct db_rrdp_uri));
	tmp->table = NULL;

	return tmp;
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

rrdp_uri_cmp_result_t
db_rrdp_uris_cmp(char const *uri, char const *session_id, unsigned long serial)
{
	struct uris_table *found;

	found = find_rrdp_uri(get_thread_rrdp_uris(), uri);
	if (found == NULL) {
		pr_val_debug("I don't have state for this Update Notification; downloading snapshot...");
		return RRDP_URI_NOTFOUND;
	}

	if (strcmp(session_id, found->data.session_id) != 0) {
		pr_val_debug("session_id changed from '%s' to '%s'.",
		    found->data.session_id, session_id);
		return RRDP_URI_DIFF_SESSION;
	}

	if (serial != found->data.serial) {
		pr_val_debug("The serial changed from %lu to %lu.",
		    found->data.serial, serial);
		return RRDP_URI_DIFF_SERIAL;
	}

	pr_val_debug("The new Update Notification has the same session_id (%s) and serial (%lu) as the old one.",
	    session_id, serial);
	return RRDP_URI_EQUAL;
}

void
db_rrdp_uris_update(char const *uri, char const *session_id,
    unsigned long serial, rrdp_req_status_t req_status,
    struct visited_uris *visited_uris)
{
	struct uris_table *db_uri;

	db_uri = uris_table_create(uri, session_id, serial, req_status);
	db_uri->visited_uris = visited_uris; /* Ownership transfered */
	add_rrdp_uri(get_thread_rrdp_uris(), db_uri);
}

int
db_rrdp_uris_get_serial(char const *uri, unsigned long *serial)
{
	struct uris_table *found;

	found = find_rrdp_uri(get_thread_rrdp_uris(), uri);
	if (found == NULL)
		return -ENOENT;

	*serial = found->data.serial;
	return 0;
}

int
db_rrdp_uris_get_last_update(char const *uri, long *date)
{
	struct uris_table *found;

	found = find_rrdp_uri(get_thread_rrdp_uris(), uri);
	if (found == NULL)
		return -ENOENT;

	*date = found->last_update;
	return 0;
}

/* Set the last update to now */
int
db_rrdp_uris_set_last_update(char const *uri)
{
	struct uris_table *found;
	time_t now;
	int error;

	found = find_rrdp_uri(get_thread_rrdp_uris(), uri);
	if (found == NULL)
		return -ENOENT;

	now = 0;
	error = get_current_time(&now);
	if (error)
		return error;

	found->last_update = (long)now;
	return 0;
}

int
db_rrdp_uris_get_request_status(char const *uri, rrdp_req_status_t *result)
{
	struct uris_table *found;

	found = find_rrdp_uri(get_thread_rrdp_uris(), uri);
	if (found == NULL)
		return -ENOENT;

	*result = found->request_status;
	return 0;
}

int
db_rrdp_uris_set_request_status(char const *uri, rrdp_req_status_t value)
{
	struct uris_table *found;

	found = find_rrdp_uri(get_thread_rrdp_uris(), uri);
	if (found == NULL)
		return -ENOENT;

	found->request_status = value;
	return 0;
}

void
db_rrdp_uris_set_all_unvisited(void)
{
	struct db_rrdp_uri *uris;
	struct uris_table *uri_node, *uri_tmp;

	uris = get_thread_rrdp_uris();
	HASH_ITER(hh, uris->table, uri_node, uri_tmp)
		uri_node->request_status = RRDP_URI_REQ_UNVISITED;
}

/*
 * Returns a pointer to the visited_uris of the current thread.
 */
struct visited_uris *
db_rrdp_uris_get_visited_uris(char const *uri)
{
	struct uris_table *found;

	found = find_rrdp_uri(get_thread_rrdp_uris(), uri);
	if (found == NULL)
		return NULL;

	return found->visited_uris;
}
