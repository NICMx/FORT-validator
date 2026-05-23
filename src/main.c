#include <errno.h>

#include "config.h"
#include "extension.h"
#include "http/http.h"
#include "log.h"
#include "nid.h"
#include "print_file.h"
#include "prometheus.h"
#include "rtr/rtr.h"
#include "stats.h"
#include "thread_var.h"
#include "xml/relax_ng.h"

static int
fort_standalone(void)
{
	int error;

	pr_op_info("Updating cache...");

	error = vrps_update(NULL);
	if (error) {
		pr_op_err("Validation unsuccessful; results unusable.");
		return error;
	}

	pr_op_info("Done.");
	return 0;
}

static int
fort_server(void)
{
	struct rtr_metadata rtr;
	int error;

	pr_op_info("Main loop: Starting...");

	error = rtr_start();
	if (error)
		return error;

	error = vrps_update(&rtr);
	if (fort_end)
		goto end;
	if (error) {
		pr_op_err("Main loop: Validation unsuccessful; results unusable.");
		goto end;
	}

	rtr_notify(&rtr);

	/* TODO (#133) Stats ready; remove this message in a couple versions. */
	pr_op_warn("First validation cycle successfully ended, now you can connect your router(s)");
	stats_gauge_set(stat_rtr_ready, 1);

	do {
		pr_op_info("Main loop: Sleeping.");
		sleep(config_get_validation_interval());
		if (fort_end)
			goto end;
		pr_op_info("Main loop: Time to work!");

		error = vrps_update(&rtr);
		if (fort_end)
			break;
		if (error) {
			pr_op_debug("Main loop: Error %d (%s)", error,
			    strerror(abs(error)));
			continue;
		}
		rtr_notify(&rtr);
	} while (true);

end:	rtr_stop();
	return error;
}

/**
 * Shells don't like it when we return values other than 0-255.
 * In fact, bash also has its own meanings for 126-255.
 * (See man 1 bash > EXIT STATUS)
 *
 * This function shifts @error to our exclusive range.
 */
static int
convert_to_result(int error)
{
	if (error == 0)
		return 0; /* Happy path */

	/* -INT_MIN overflows, So handle weird case. */
	if (error == INT_MIN)
		return 125;

	/* Force range 0-127 */
	if (error < 0)
		error = -error;
	error &= 0x7F;

	switch (error) {
	case 126:
		return 122;
	case 127:
		return 123;
	case 0:
		return 124; /* was divisible by 128; force error. */
	}
	return error;
}

int
main(int argc, char **argv)
{
	int error;

	/* Initializations */

	error = log_setup(false);
	if (error)
		goto just_quit;

	error = thvar_init();
	if (error)
		goto revert_log;
	error = incidence_init();
	if (error)
		goto revert_log;
	error = handle_flags_config(argc, argv);
	if (error)
		goto revert_log;
	error = stats_setup();
	if (error)
		goto revert_config;
	error = prometheus_setup();
	if (error)
		goto revert_stats;
	error = nid_init();
	if (error)
		goto revert_prometheus;
	error = extension_init();
	if (error)
		goto revert_nid;
	error = http_init();
	if (error)
		goto revert_nid;

	error = relax_ng_init();
	if (error)
		goto revert_http;

	/* Meat */

	switch (config_get_mode()) {
	case STANDALONE:
		error = fort_standalone();
		break;
	case SERVER:
		error = fort_server();
		break;
	case PRINT_FILE:
		error = print_file();
		break;
	}

	/* End */

	relax_ng_cleanup();
revert_http:
	http_cleanup();
revert_nid:
	nid_destroy();
revert_prometheus:
	prometheus_teardown();
revert_stats:
	stats_teardown();
revert_config:
	free_rpki_config();
revert_log:
	log_teardown();
just_quit:
	return convert_to_result(error);
}
