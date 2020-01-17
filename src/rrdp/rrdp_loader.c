#include "rrdp_loader.h"

#include "rrdp/db/db_rrdp_uris.h"
#include "rrdp/rrdp_objects.h"
#include "rrdp/rrdp_parser.h"
#include "config.h"
#include "log.h"
#include "thread_var.h"
#include "visited_uris.h"

/* Fetch and process the deltas from the @notification */
static int
process_diff_serial(struct update_notification *notification,
    struct visited_uris **visited)
{
	unsigned long serial;
	int error;

	error = db_rrdp_uris_get_serial(notification->uri, &serial);
	if (error)
		return error;

	/* Work with the existent visited uris */
	error = db_rrdp_uris_get_visited_uris(notification->uri, visited);
	if (error)
		return error;

	return rrdp_process_deltas(notification, serial, *visited);
}

/* Fetch and process the snapshot from the @notification */
static int
process_snapshot(struct update_notification *notification,
    struct visited_uris **visited)
{
	struct visited_uris *tmp;
	int error;

	/* Use a new allocated visited_uris struct */
	error = visited_uris_create(&tmp);
	if (error)
		return error;

	error = rrdp_parse_snapshot(notification, tmp);
	if (error) {
		visited_uris_refput(tmp);
		return error;
	}

	*visited = tmp;
	return 0;
}

static int
remove_rrdp_uri_files(char const *notification_uri)
{
	struct visited_uris *tmp;
	int error;

	/* Work with the existent visited uris */
	error = db_rrdp_uris_get_visited_uris(notification_uri, &tmp);
	if (error)
		return error;

	return visited_uris_remove_local(tmp);
}

/* Mark the URI as errored with dummy data, so it won't be requested again */
static int
mark_rrdp_uri_request_err(char const *notification_uri)
{
	struct visited_uris *tmp;
	int error;

	pr_debug("RRDP data of '%s' won't be requested again during this cycle due to previous error.",
	    notification_uri);

	error = visited_uris_create(&tmp);
	if (error)
		return error;

	error = db_rrdp_uris_update(notification_uri, "", 0,
	    RRDP_URI_REQ_ERROR, tmp);
	if (error) {
		visited_uris_refput(tmp);
		return error;
	}

	return 0;
}

/*
 * Try to get RRDP Update Notification file and process it accordingly.
 *
 * If there's an error that could lead to an inconsistent local repository
 * state, marks the @uri as error'd so that it won't be requested again during
 * the same validation cycle.
 *
 * If there are no errors, updates the local DB and marks the @uri as visited.
 *
 * If the @uri is being visited again, verify its previous visit state. If there
 * were no errors, just return success; otherwise, return error code -EPERM.
 */
int
rrdp_load(struct rpki_uri *uri)
{
	struct update_notification *upd_notification;
	struct visited_uris *visited;
	rrdp_req_status_t requested;
	rrdp_uri_cmp_result_t res;
	int error, upd_error;

	if (!config_get_rrdp_enabled())
		return 0;

	/* Avoid multiple requests on the same run */
	requested = RRDP_URI_REQ_UNVISITED;
	error = db_rrdp_uris_get_request_status(uri_get_global(uri), &requested);
	if (error && error != -ENOENT)
		return error;

	switch(requested) {
	case RRDP_URI_REQ_VISITED:
		return 0;
	case RRDP_URI_REQ_UNVISITED:
		break;
	case RRDP_URI_REQ_ERROR:
		/* Log has been done before this call */
		return -EPERM;
	}

	error = rrdp_parse_notification(uri, &upd_notification);
	if (error)
		goto upd_error;

	/* No updates at the file (yet), didn't pushed to fnstack */
	if (upd_notification == NULL) {
		pr_debug("No updates yet at '%s'.", uri_get_global(uri));
		return 0;
	}

	error = db_rrdp_uris_cmp(uri_get_global(uri),
	    upd_notification->global_data.session_id,
	    upd_notification->global_data.serial,
	    &res);
	if (error)
		goto upd_destroy;

	switch (res) {
	case RRDP_URI_EQUAL:
		goto set_update;
	case RRDP_URI_DIFF_SERIAL:
		error = process_diff_serial(upd_notification, &visited);
		if (!error) {
			visited_uris_refget(visited);
			break;
		}
		/* Something went wrong, use snapshot */
		pr_warn("There was an error processing RRDP deltas, using the snapshot instead.");
	case RRDP_URI_DIFF_SESSION:
		/* Delete the old session files */
		error = remove_rrdp_uri_files(upd_notification->uri);
		if (error)
			break;
	case RRDP_URI_NOTFOUND:
		error = process_snapshot(upd_notification, &visited);
		break;
	default:
		pr_crit("Unexpected RRDP URI comparison result");
	}

	if (error)
		goto upd_destroy;

	/* Any update, and no error during the process, update db as well */
	pr_debug("Updating local RRDP data of '%s' to:", uri_get_global(uri));
	pr_debug("- Session ID: %s", upd_notification->global_data.session_id);
	pr_debug("- Serial: %lu", upd_notification->global_data.serial);
	error = db_rrdp_uris_update(uri_get_global(uri),
	    upd_notification->global_data.session_id,
	    upd_notification->global_data.serial,
	    RRDP_URI_REQ_VISITED,
	    visited);
	if (error)
		goto upd_destroy;

set_update:
	/* Set the last update to now */
	pr_debug("Set last update of RRDP data of '%s' to now.",
	    uri_get_global(uri));
	db_rrdp_uris_set_last_update(uri_get_global(uri));
upd_destroy:
	if (upd_notification != NULL) {
		update_notification_destroy(upd_notification);
		fnstack_pop(); /* Pop from rrdp_parse_notification */
	}
upd_error:
	/* Don't fall here on success */
	if (error) {
		upd_error = mark_rrdp_uri_request_err(uri_get_global(uri));
		if (upd_error)
			return upd_error;
	}
	return error;
}
