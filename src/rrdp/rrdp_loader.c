#include "rrdp_loader.h"

#include "rrdp/db/db_rrdp_uris.h"
#include "rrdp/rrdp_objects.h"
#include "rrdp/rrdp_parser.h"
#include "rsync/rsync.h"
#include "common.h"
#include "config.h"
#include "log.h"
#include "reqs_errors.h"
#include "thread_var.h"
#include "visited_uris.h"

/* Fetch and process the deltas from the @notification */
static int
process_diff_serial(struct update_notification *notification,
    bool log_operation, struct visited_uris **visited)
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

	return rrdp_process_deltas(notification, serial, *visited,
	    log_operation);
}

/* Fetch and process the snapshot from the @notification */
static int
process_snapshot(struct update_notification *notification, bool log_operation,
    struct visited_uris **visited)
{
	struct visited_uris *tmp;
	int error;

	/* Use a new allocated visited_uris struct */
	error = visited_uris_create(&tmp);
	if (error)
		return error;

	error = rrdp_parse_snapshot(notification, tmp, log_operation);
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
	char const *workspace;
	int error;

	/* Work with the existent visited uris */
	error = db_rrdp_uris_get_visited_uris(notification_uri, &tmp);
	if (error)
		return error;

	workspace = db_rrdp_uris_workspace_get();

	return visited_uris_delete_local(tmp, workspace);
}

/* Mark the URI as errored with dummy data, so it won't be requested again */
static int
mark_rrdp_uri_request_err(char const *notification_uri)
{
	struct visited_uris *tmp;
	int error;

	pr_val_debug("RRDP data of '%s' won't be requested again during this cycle due to previous error.",
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

static int
process_diff_session(struct update_notification *notification,
    bool log_operation, struct visited_uris **visited)
{
	int error;

	error = remove_rrdp_uri_files(notification->uri);
	if (error)
		return error;

	return process_snapshot(notification, log_operation, visited);
}

/*
 * Downloads the Update Notification pointed by @uri, and updates the cache
 * accordingly.
 *
 * "Updates the cache accordingly" means it downloads the missing deltas or
 * snapshot, and explodes them into the corresponding RPP's local directory.
 * Calling code can then access the files, just as if they had been downloaded
 * via rsync.
 */
static int
__rrdp_load(struct rpki_uri *uri, bool force_snapshot, bool *data_updated)
{
	struct update_notification *upd_notification;
	struct visited_uris *visited;
	rrdp_req_status_t requested;
	rrdp_uri_cmp_result_t res;
	bool log_operation;
	int error, upd_error;

	(*data_updated) = false;

#ifndef DEBUG_RRDP
	/*
	 * In normal mode (DEBUG_RRDP disabled), RRDP files (notifications,
	 * snapshots and deltas) are not cached.
	 * I think it was implemented this way to prevent the cache from growing
	 * indefinitely. (Because otherwise Fort would lose track of RRDP files
	 * from disappearing CAs. RRDP files are designed to be relevant on
	 * single validation runs anyway.)
	 * Note that __rrdp_load() includes the RRDP file explosion. Exploded
	 * files (manifests, certificates, ROAs and ghostbusters) are cached as
	 * usual.
	 *
	 * Therefore, in normal offline mode, the entirety of __rrdp_load()
	 * needs to be skipped because it would otherwise error out while
	 * attempting to access the nonexistent RRDP files.
	 *
	 * But if you need to debug RRDP files specifically, their persistent
	 * deletions will force you to debug them in online mode.
	 *
	 * That's why DEBUG_RRDP exists. When it's enabled, RRDP files will not
	 * be deleted, and config_get_http_enabled() will kick off during
	 * __http_download_file(). This will allow you to reach the RRDP file
	 * parsing code in offline mode.
	 *
	 * I know this is somewhat convoluted, but I haven't found a more
	 * elegant way to do it.
	 *
	 * Simple enable example: `make FORT_FLAGS=-DDEBUG_RRDP`
	 */
	if (!config_get_http_enabled()) {
		(*data_updated) = true;
		return 0;
	}
#endif

	/* Avoid multiple requests on the same run */
	requested = RRDP_URI_REQ_UNVISITED;
	error = db_rrdp_uris_get_request_status(uri_get_global(uri),
	    &requested);
	if (error && error != -ENOENT)
		return error;

	if (!force_snapshot) {
		switch(requested) {
		case RRDP_URI_REQ_VISITED:
			(*data_updated) = true;
			return 0;
		case RRDP_URI_REQ_UNVISITED:
			break;
		case RRDP_URI_REQ_ERROR:
			/* Log has been done before this call */
			return -EPERM;
		}
	} else {
		if (requested != RRDP_URI_REQ_VISITED) {
			pr_val_info("Skipping RRDP snapshot reload");
			return -EINVAL;
		}
	}

	pr_val_debug("Downloading RRDP Update Notification...");
	log_operation = reqs_errors_log_uri(uri_get_global(uri));
	error = rrdp_parse_notification(uri, log_operation, force_snapshot,
	    &upd_notification);
	if (error)
		goto upd_end;

	/* No updates at the file (yet), didn't pushed to fnstack */
	if (upd_notification == NULL) {
		pr_val_debug("The Update Notification has not changed.");
		goto upd_end;
	}

	pr_val_debug("The Update Notification changed.");

	do {
		/* Same flow as a session update */
		if (force_snapshot) {
			error = process_diff_session(upd_notification,
			    log_operation, &visited);
			if (error)
				goto upd_destroy;
			(*data_updated) = true;
			break;
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
		case RRDP_URI_DIFF_SESSION:
			/* Delete the old session files */
			error = process_diff_session(upd_notification,
			    log_operation, &visited);
			if (error)
				goto upd_destroy;
			(*data_updated) = true;
			break;
		case RRDP_URI_DIFF_SERIAL:
			error = process_diff_serial(upd_notification,
			    log_operation, &visited);
			if (!error) {
				visited_uris_refget(visited);
				(*data_updated) = true;
				break;
			}
			/* Something went wrong, use snapshot */
			pr_val_info("There was an error processing RRDP deltas, using the snapshot instead.");
		case RRDP_URI_NOTFOUND:
			error = process_snapshot(upd_notification, log_operation,
			    &visited);
			if (error)
				goto upd_destroy;
			(*data_updated) = true;
			break;
		default:
			pr_crit("Unexpected RRDP URI comparison result");
		}
	} while (0);

	/* Any update, and no error during the process, update db as well */
	pr_val_debug("Updating local RRDP data of '%s' to:", uri_get_global(uri));
	pr_val_debug("- Session ID: %s", upd_notification->global_data.session_id);
	pr_val_debug("- Serial: %lu", upd_notification->global_data.serial);
	error = db_rrdp_uris_update(uri_get_global(uri),
	    upd_notification->global_data.session_id,
	    upd_notification->global_data.serial,
	    RRDP_URI_REQ_VISITED,
	    visited);
	if (error)
		goto upd_destroy;

set_update:
	/* Set the last update to now */
	pr_val_debug("Set last update of RRDP data of '%s' to now.",
	    uri_get_global(uri));
	db_rrdp_uris_set_last_update(uri_get_global(uri));
upd_destroy:
	if (upd_notification != NULL) {
		update_notification_destroy(upd_notification);
		fnstack_pop(); /* Pop from rrdp_parse_notification */
	}
upd_end:
	/* Just return on success */
	if (!error) {
		/* The repository URI is the notification file URI */
		reqs_errors_rem_uri(uri_get_global(uri));
		return 0;
	}

	/* Request failed, store the repository URI */
	if (error == EREQFAILED) {
		upd_error = reqs_errors_add_uri(uri_get_global(uri));
		if (upd_error)
			return upd_error;
	} else {
		/* Reset RSYNC visited URIs, this may force the update */
		/* TODO um, what? */
		reset_downloaded();
	}

	upd_error = mark_rrdp_uri_request_err(uri_get_global(uri));
	if (upd_error)
		return upd_error;

	return error;
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
 *
 * @data_updated will be true if:
 * - Delta files were processed,
 * - Snapshot file was processed,
 * - or @uri was already visited at this cycle
 */
int
rrdp_load(struct rpki_uri *uri, bool *data_updated)
{
	return __rrdp_load(uri, false, data_updated);
}

/*
 * Force the processing of the snapshot. The update notification is requested
 * again, omitting the 'If-Modified-Since' header at the HTTP request.
 *
 * Shouldn't be called if @uri had a previous error or hasn't been requested,
 * still the check is done.
 */
int
rrdp_reload_snapshot(struct rpki_uri *uri)
{
	bool tmp;

	tmp = false;
	return __rrdp_load(uri, true, &tmp);
}
