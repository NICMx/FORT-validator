#include <errno.h>
#include <syslog.h>

#include "cache.h"
#include "common.h"
#include "config.h"
#include "daemon.h"
#include "ext.h"
#include "hash.h"
#include "http.h"
#include "log.h"
#include "nid.h"
#include "output_printer.h"
#include "prometheus.h"
#include "rsync.h"
#include "rtr/db/vrps.h"
#include "rtr/rtr.h"
#include "sig.h"
#include "stats.h"
#include "task.h"
#include "thread_var.h"

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
		sleep(fortcfg.interval);
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
fort_cycle(int argc, char **argv)
{
	init_verdict verdict;
	int error;

	/* DO NOT START ANY THREADS UNTIL WE'RE DONE fork()ING. */
	/* DO NOT INSTALL SIGNAL HANDLERS UNTIL WE'RE DONE DAEMONIZING. */
	/* Also: Daemonizing will close all file descriptors. */

	verdict = handle_flags_config(argc, argv);
	if (verdict == IV_FAIL)
		return EINVAL;
	if (verdict == IV_DONE)
		return 0;

	if (fortcfg.daemon) {
		verdict = daemonize(); /* fork */
		if (verdict == IV_FAIL) {
			error = EINVAL;
			goto revert_config;
		}
		if (verdict == IV_DONE) {
			error = 0;
			goto revert_config;
		}

		set_logger_syslog(); /* XXX hardcoded */
	} else {
		set_logger_console(); /* XXX hardcoded */
	}

	/* Needs to happen before drop_privileges() if port < 1024 */
	if (fortcfg.mode == SERVER) {
		error = rtr_setup();
		if (error)
			goto revert_daemon;
	}

	error = drop_privileges();
	if (error)
		goto revert_rtr;

	error = cache_setup_wd();
	if (error)
		goto revert_rtr;

	rsync_setup(); /* fork then thread */

	/*
	 * cache_setup_lock() needs to happen after daemonize(), because it
	 * wants to print the grandchild's PID in the lockfile, not the
	 * grandparent's.
	 *
	 * cache_setup_lock (CSL) and register_signal_handlers (RGS) need to
	 * happen as close to each other as possible.
	 *
	 * Suppose we get SIGTERM between these functions...
	 *
	 * 1. CSL then RGS, we're interrupted between them:
	 *    The signal handler doesn't delete our lock.
	 * 2. RGS then CSL, we're interrupted between them:
	 *    The signal handler deletes some other instance's lock.
	 *
	 * 1 is better because we already couldn't guarantee the lock was
	 * deleted in every situation. (SIGKILL, or register_signal_handlers()
	 * fails to install some handler.)
	 */
	error = cache_setup_lock();
	if (error)
		goto revert_rsync;
	register_signal_handlers();

	error = thvar_init();
	if (error)
		goto revert_rsync;
	error = stats_setup();
	if (error)
		goto revert_rsync;

	/*
	 * Notice we're doing this after dropping privileges.
	 * This means Prometheus will not be bound to ports < 1024, even if the
	 * user starts us as root.
	 * Unless the environment is Linux, and the user starts us with network
	 * capabilities or whatever.
	 * I'm OK with this. microhttpd is kind of illegible, so I'm not eager
	 * to give it opportunities to mess up.
	 */
	error = prometheus_setup(); /* likely starts threads */
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
	cache_setup_tables();
	error = output_setup();
	if (error)
		goto revert_http;
	task_setup();

	/* Meat */

	switch (fortcfg.mode) {
	case STANDALONE:
		error = fort_standalone(); /* starts threads */
		break;
	case SERVER:
		error = fort_server(); /* starts threads */
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
revert_rtr:
	if (fortcfg.mode == SERVER)
		rtr_teardown();
revert_daemon:
	daemon_teardown();
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
	int error;

	log_setup();

	error = fort_cycle(argc, argv);

	log_teardown();
	return convert_to_result(error);
}
