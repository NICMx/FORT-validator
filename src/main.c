#include <errno.h>

#include "cache.h"
#include "common.h"
#include "config.h"
#include "ext.h"
#include "hash.h"
#include "http.h"
#include "log.h"
#include "nid.h"
#include "output_printer.h"
#include "print_file.h"
#include "prometheus.h"
#include "rsync.h"
#include "rtr/db/vrps.h"
#include "rtr/rtr.h"
#include "sig.h"
#include "stats.h"
#include "task.h"
#include "thread_var.h"

#include <syslog.h>

static int
fort_standalone(void)
{
	int error;

	pr_inf("Updating cache...");

	error = vrps_update(NULL);
	if (error) {
		pr_err("Validation unsuccessful; results unusable.");
		return error;
	}

	pr_inf("Done.");
	return 0;
}

static int
fort_server(void)
{
	struct rtr_metadata rtr;
	int error;

	pr_inf("Main loop: Starting...");

	error = rtr_start();
	if (error)
		return error;

	error = vrps_update(&rtr);
	if (error) {
		pr_err("Main loop: Validation unsuccessful; results unusable.");
		goto end;
	}

	rtr_notify(&rtr);

	stats_gauge_set(stat_rtr_ready, 1);

	while (!fort_end) {
		pr_inf("Main loop: Sleeping.");
		sleep(config_get_validation_interval());
		if (fort_end)
			break;
		pr_inf("Main loop: Time to work!");

		error = vrps_update(&rtr);
		if (fort_end || error == EINTR)
			break;
		if (error) {
			pr_trc("Main loop: %s", strerror(abs(error)));
			continue;
		}
		rtr_notify(&rtr);
	}

end:	rtr_stop();
	return error;
}

static int
fort_cycle(int argc, char **argv, bool serve)
{
	init_verdict verdict;
	int error;

	/* DO NOT START ANY THREADS UNTIL WE'RE DONE fork()ING. */

	verdict = handle_flags_config(argc - 1, argv + 1);
	if (verdict == IV_FAIL)
		return EINVAL;
	if (verdict == IV_DONE)
		return 0;

	error = cache_setup1();
	if (error)
		goto revert_config;

	rsync_setup(); /* Fork rsync spawner ASAP */
	register_signal_handlers();

	error = thvar_init();
	if (error)
		goto revert_rsync;
	error = stats_setup();
	if (error)
		goto revert_rsync;
	error = prometheus_setup();
	if (error)
		goto revert_stats;
	error = nid_init();
	if (error)
		goto revert_prometheus;
	error = extension_init();
	if (error)
		goto revert_nid;
	error = hash_setup();
	if (error)
		goto revert_nid;
	error = http_init();
	if (error)
		goto revert_hash;
	error = cache_setup2();
	if (error)
		goto revert_http;
	error = output_setup();
	if (error)
		goto revert_http;
	task_setup();

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
	task_teardown();
revert_http:
	http_cleanup();
revert_hash:
	hash_teardown();
revert_nid:
	nid_destroy();
revert_prometheus:
	prometheus_teardown();
revert_stats:
	stats_teardown();
revert_rsync:
	rsync_teardown();
revert_config:
	free_rpki_config();
	return error;
}

/*
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
	char const *mode;
	int error;

	log_setup();

	mode = (argc <= 1) ? "serve" : argv[1];

	if (strcmp(mode, "serve") == 0)
		error = fort_cycle(argc, argv, true);
	else if (strcmp(mode, "step") == 0)
		error = fort_cycle(argc, argv, false);
	else
		error = pr_err("Unknown mode: %s", mode);

	log_teardown();
	return convert_to_result(error);
}
