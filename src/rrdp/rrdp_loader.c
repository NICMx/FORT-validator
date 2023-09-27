#include "rrdp/rrdp_loader.h"

#include <errno.h>
#include <sys/stat.h>

#include "log.h"
#include "thread_var.h"
#include "rrdp/rrdp_objects.h"
#include "rrdp/rrdp_parser.h"
#include "cache/local_cache.h"

static int
get_metadata(struct rpki_uri *uri, struct notification_metadata *result)
{
	struct stat st;
	struct update_notification notification;
	int error;

	result->session_id = NULL;
	result->serial = 0;

	if (stat(uri_get_local(uri), &st) != 0) {
		error = errno;
		return (error == ENOENT) ? 0 : error;
	}

	/*
	 * TODO (fine) optimize by not reading everything,
	 * or maybe keep it if it doesn't change.
	 */
	error = rrdp_parse_notification(uri, &notification);
	if (error)
		return error;

	*result = notification.meta;

	update_notification_destroy(&notification);
	return 0;
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
int
rrdp_update(struct rpki_uri *uri)
{
	struct notification_metadata old;
	struct update_notification new;
	bool changed;
	int error;

	if (uri == NULL || !uri_is_https(uri))
		pr_crit("Wrong call, trying to parse a non HTTPS URI");

	fnstack_push_uri(uri);
	pr_val_debug("Processing notification.");

	error = get_metadata(uri, &old);
	if (error)
		goto end;
	pr_val_debug("Old session/serial: %s/%lu", old.session_id, old.serial);

	error = cache_download(uri, &changed);
	if (error)
		goto end;
	if (!changed) {
		pr_val_debug("The Notification has not changed.");
		goto end;
	}

	error = rrdp_parse_notification(uri, &new);
	if (error)
		goto end; /* FIXME fall back to previous? */
	pr_val_debug("New session/serial: %s/%lu", new.meta.session_id,
	    new.meta.serial);

	if (old.session_id == NULL) {
		pr_val_debug("This is a new Notification.");
		error = rrdp_parse_snapshot(&new);
		goto revert_notification;
	}

	if (strcmp(old.session_id, new.meta.session_id) != 0) {
		pr_val_debug("The Notification's session ID changed.");
		error = rrdp_parse_snapshot(&new);
		goto revert_notification;
	}

	if (old.serial != new.meta.serial) {
		pr_val_debug("The Notification' serial changed.");
		error = rrdp_process_deltas(&new, old.serial);
		goto revert_notification;
	}

	pr_val_debug("The Notification changed, but the session ID and serial didn't.");

revert_notification:
	update_notification_destroy(&new);

end:	notification_metadata_cleanup(&old);

	/* TODO (fine) hideous function side effect; find a better way. */
	if (!error)
		validation_set_notification_uri(state_retrieve(), uri);

	fnstack_pop();
	return error;
}
