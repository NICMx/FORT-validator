#include "rrdp_loader.h"

#include "rrdp/db/db_rrdp_uris.h"
#include "rrdp/rrdp_objects.h"
#include "rrdp/rrdp_parser.h"
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

int
rrdp_load(struct rpki_uri *uri)
{
	struct update_notification *upd_notification;
	struct visited_uris *visited;
	rrdp_uri_cmp_result_t res;
	int error;
	bool requested;

	/* Avoid multiple requests on the same run */
	requested = false;
	error = db_rrdp_uris_get_requested(uri_get_global(uri), &requested);
	if (error && error != -ENOENT)
		return error;

	if (requested)
		return 0;

	error = rrdp_parse_notification(uri, &upd_notification);
	if (error)
		return error;

	/* No updates at the file (yet), didn't pushed to fnstack */
	if (upd_notification == NULL)
		return 0;

	error = db_rrdp_uris_cmp(uri_get_global(uri),
	    upd_notification->global_data.session_id,
	    upd_notification->global_data.serial,
	    &res);
	if (error)
		goto end;

	switch (res) {
	case RRDP_URI_EQUAL:
		goto set_update;
	case RRDP_URI_DIFF_SERIAL:
		error = process_diff_serial(upd_notification, &visited);
		/* Something went wrong, use snapshot */
		if (!error) {
			visited_uris_refget(visited);
			break;
		}
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

	/* Any change, and no error during the process, update db */
	if (!error) {
		error = db_rrdp_uris_update(uri_get_global(uri),
		    upd_notification->global_data.session_id,
		    upd_notification->global_data.serial,
		    visited);
		if (error)
			goto end;
	}

set_update:
	/* Set the last update to now */
	error = db_rrdp_uris_set_last_update(uri_get_global(uri));
end:
	if (upd_notification != NULL) {
		update_notification_destroy(upd_notification);
		fnstack_pop(); /* Pop from rrdp_parse_notification */
	}

	return error;
}
