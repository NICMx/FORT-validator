#include "validation_run.h"

#include <errno.h>

#include "config.h"
#include "log.h"
#include "notify.h"
#include "config/mode.h"
#include "rtr/db/vrps.h"

/* Runs a single cycle, use at standalone mode or before running RTR server */
int
validation_run_first(void)
{
	pr_op_info("Please wait. Validating...");

	if (vrps_update(NULL) != 0)
		return pr_op_err("Validation unsuccessful; results unusable.");

	if (config_get_mode() == SERVER)
		pr_op_info("Validation complete; waiting for routers.");
	else
		pr_op_info("Validation complete.");

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
