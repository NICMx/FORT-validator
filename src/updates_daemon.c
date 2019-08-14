#include "updates_daemon.h"

#include <errno.h>
#include <stdbool.h>
#include <unistd.h>

#include "common.h"
#include "config.h"
#include "log.h"
#include "notify.h"
#include "object/tal.h"
#include "rtr/db/vrps.h"

static pthread_t thread;

static void *
check_vrps_updates(void *param_void)
{
	bool changed;
	int error;

	do {
		error = vrps_update(&changed);
		if (error == -EINTR)
			break; /* Process interrupted, terminate thread */

		if (error) {
			pr_err("Error code %d while trying to update the ROA database. Sleeping...",
			    error);
			goto sleep;
		}

		if (changed) {
			error = notify_clients();
			if (error)
				pr_debug("Could not notify clients of the new VRPs. (Error code %d.) Sleeping...",
				    error);
			else
				pr_debug("Database updated successfully. Sleeping...");
		}

sleep:
		sleep(config_get_validation_interval());
	} while (true);

	return NULL;
}

int
updates_daemon_start(void)
{
	errno = pthread_create(&thread, NULL, check_vrps_updates, NULL);
	if (errno)
		return -pr_errno(errno,
		    "Could not spawn the update daemon thread");

	return 0;
}

void
updates_daemon_destroy(void)
{
	close_thread(thread, "Validation");
}
