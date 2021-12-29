#include "rrdp/rrdp.h"

#include "log.h"
#include "rpp/rpp_dl_status.h"
#include "thread_var.h"
#include "rrdp/types.h"
#include "rrdp/delta.h"
#include "rrdp/notification.h"
#include "rrdp/snapshot.h"

/*
 * RRDP entry point.
 * Downloads the Update Notification file pointed by @guri. If there are
 * changes, downloads and explodes the snapshot or the new deltas.
 *
 * Returns zero if our cached version of the repository is now up-to-date
 * (regardless of whether it was downloaded or not), nonzero otherwise.
 */
int
rrdp_update(struct rpki_uri *uri)
{
	struct rrdp_notification old, new;
	int error;

	pr_val_debug("RRDP Notification '%s' {", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	/* Avoid multiple identical requests in the same cycle */
	switch (rdsdb_get(uri)) {
	case RDS_NOT_YET:
		break;
	case RDS_SUCCESS:
		pr_val_debug("This RPP was already successfully updated in the current validation cycle.");
		error = 0;
		goto end;
	case RDS_ERROR:
		pr_val_err("This RPP was already unsuccessfully updated in the current validation cycle; not retrying.");
		error = -EPERM;
		goto end;
	}

	rrdp_notification_init(&old, uri);
	rrdp_notification_init(&new, uri);

	error = rrdp_parse_notification(&old, &new);
	if (error)
		goto cleanup;

	if (old.session.id == NULL || strcmp(old.session.id, new.session.id) != 0)
		error = rrdp_parse_snapshot(&new);
	else if (old.session.serial != new.session.serial)
		error = rrdp_process_deltas(&old, &new);

cleanup:
	rrdp_notification_cleanup(&old);
	rrdp_notification_cleanup(&new);
	rdsdb_set(uri, error);
end:
	fnstack_pop();
	pr_val_debug("}");
	return error;
}
