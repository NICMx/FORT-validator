#include "validation_run.h"

#include <stdbool.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "notify.h"
#include "rtr/db/vrps.h"

/* Runs a single cycle, use at standalone mode or before running RTR server */
int
validation_run_first(void)
{
	bool upd;
	int error;

	upd = false;
	error = vrps_update(&upd);
	if (error)
		return pr_op_err("First validation wasn't successful.");

	return 0;
}

/* Run a validation cycle each 'server.interval.validation' secs */
int
validation_run_cycle(void)
{
	unsigned int validation_interval;
	bool changed;
	int error;

	validation_interval = config_get_validation_interval();
	do {
		sleep(validation_interval);

		error = vrps_update(&changed);
		if (error == -EINTR)
			break; /* Process interrupted, terminate thread */

		if (error) {
			pr_op_err("Error while trying to update the ROA database. Sleeping...");
			continue;
		}

		if (changed) {
			error = notify_clients();
			if (error)
				pr_op_debug("Couldn't notify clients of the new VRPs. (Error code %d.) Sleeping...",
				    error);
			else
				pr_op_debug("Database updated successfully. Sleeping...");
		}
	} while (true);

	return error;
}
