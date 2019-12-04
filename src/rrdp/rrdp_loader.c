#include "rrdp_loader.h"

#include "rrdp/rrdp_handler.h"
#include "rrdp/rrdp_objects.h"
#include "rrdp/rrdp_parser.h"
#include "log.h"
#include "thread_var.h"

/* Fetch and process the deltas from the @notification located at @uri */
static int
process_diff_serial(struct update_notification *notification, char const *uri)
{
	unsigned long serial;
	int error;

	error = rhandler_uri_get_serial(uri, &serial);
	if (error)
		return error;

	return rrdp_process_deltas(notification, serial);
}

/* Fetch and process the snapshot from the @notification located at @uri */
static int
process_snapshot(struct update_notification *notification, char const *uri)
{
	return rrdp_parse_snapshot(notification);
}

int
rrdp_load(struct rpki_uri *uri)
{
	struct update_notification *upd_notification;
	long last_update;
	enum rrdp_uri_cmp_result res;
	int error;

	last_update = 0;
	error = rhandler_uri_get_last_update(uri_get_global(uri), &last_update);
	if (error && error != -ENOENT)
		return error;

	error = rrdp_parse_notification(uri, last_update, &upd_notification);
	if (error)
		return error;

	/* No updates at the file (yet) */
	if (upd_notification == NULL)
		return 0;

	res = rhandler_uri_cmp(uri_get_global(uri),
	    upd_notification->global_data.session_id,
	    upd_notification->global_data.serial);
	switch(res) {
	case RRDP_URI_EQUAL:
		goto set_update;
	case RRDP_URI_DIFF_SERIAL:
		error = process_diff_serial(upd_notification,
		    uri_get_global(uri));
		break;
	case RRDP_URI_DIFF_SESSION:
		/* FIXME (now) delete the old session files */
	case RRDP_URI_NOTFOUND:
		error = process_snapshot(upd_notification, uri_get_global(uri));
		break;
	default:
		pr_crit("Unexpected RRDP URI comparison result");
	}

	/* Any change, and no error during the process, update db */
	if (!error) {
		error = rhandler_uri_update(uri_get_global(uri),
		    upd_notification->global_data.session_id,
		    upd_notification->global_data.serial);
		if (error)
			goto end;
	}

set_update:
	/* Set the last update to now */
	error = rhandler_uri_set_last_update(uri_get_global(uri));
end:
	update_notification_destroy(upd_notification);
	fnstack_pop(); /* Pop from rrdp_parse_notification */

	return error;
}
