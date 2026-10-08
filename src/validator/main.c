#include <errno.h>

#include "common/config.h"
#include "common/log.h"
#include "validator/config.h"
#include "validator/db/vrps.h"
#include "validator/ext.h"
#include "validator/hash.h"
#include "validator/http.h"
#include "validator/nid.h"
#include "validator/output_printer.h"
#include "validator/prometheus.h"
#include "validator/rsync.h"
#include "validator/sig.h"
#include "validator/stats.h"
#include "validator/task.h"
#include "validator/thread_var.h"

volatile bool fort_end = false;

static int
fort_standalone(void)
{
	int error;

	pr_trc("Updating cache...");

	error = vrps_update();
	if (error) {
		pr_err("Validation unsuccessful; results unusable.");
		return error;
	}

	pr_trc("Done.");
	return 0;
}

static int
fort_server(void)
{
	int error;

	pr_inf("Main loop: Starting...");

	error = vrps_update();
	if (error) {
		pr_err("Main loop: Validation unsuccessful; results unusable.");
		return error;
	}

	/* XXX server needs to reimplement notify */

	stats_gauge_set(stat_rtr_ready, 1);

	while (!fort_end) {
		pr_inf("Main loop: Sleeping.");
		sleep(fortcfg.validation_interval);
		if (fort_end)
			break;
		pr_inf("Main loop: Time to work!");

		error = vrps_update();
		if (fort_end || error == EINTR)
			break;
		if (error) {
			pr_trc("Main loop: %s", strerror(abs(error)));
			continue;
		}
	}

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
	init_verdict verdict;
	int error;

	log_setup();

	/* DO NOT START ANY THREADS UNTIL WE'RE DONE fork()ING. */

	verdict = handle_flags_config(argc, argv);
	if (verdict == IV_FAIL) {
		error = EINVAL;
		goto log;
	}
	if (verdict == IV_DONE) {
		error = 0;
		goto log;
	}

	error = cache_setup1();
	if (error)
		goto revert_config;

	rsync_setup();

	/* Forks done */

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

	/* XXX preserve print_file()? */
	error = (fortcfg.validation_interval == 0)
	    ? fort_standalone()
	    : fort_server();

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
	free_rpki_config(&fortcfg);
log:	log_teardown();
	return convert_to_result(error);
}
