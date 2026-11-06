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
#include "report.h"
#include "rsync.h"
#include "rtr/rtr.h"
#include "sig.h"
#include "slurm/slurm_loader.h"
#include "stats.h"
#include "task.h"
#include "types/fnstack.h"

static int
queue_tal(char const *tal_path, void *arg)
{
	if (task_enqueue_tal(tal_path) < 1) {
		pr_err("Could not enqueue task '%s'; abandoning validation.",
		    tal_path);
		return EINVAL;
	}

	return 0;
}

static void *
claim_work(void *arg)
{
	struct validation_task *task = NULL;
	struct validation_thread *vt = arg;
	validation_verdict vv;

	fnstack_init();

	while ((task = task_dequeue(task)) != NULL) {
		pr_trc("Dequeued task: %s", task_name(task));

		switch (task->type) {
		case VTT_RPP:
			vv = cer_traverse(vt, task->u.ca);
			if (vv == VV_BUSY) {
				task_requeue_dormant(task);
				task = NULL;
			}
			break;
		case VTT_TAL:
			vv = tal_traverse(vt, task->u.tal);
			if (vv == VV_BUSY) {
				task_requeue_dormant(task);
				task = NULL;
			} else if (vv == VV_FAIL) {
				task_cancel();
			}
			break;
		default:
			vv = VV_FAIL;
		}

		pr_trc("Task ended. Status: %s", vv);
	}

	return NULL;
}

static int
clean_and_export_vpt(struct vp_table *vpt)
{
	int error;

	error = slurm_apply(vpt);
	if (error)
		return error;
	vpt_sort(vpt);

	error = vpt_cache(vpt);
	if (error)
		return error;
	output_print_data(vpt);

	return 0;
}

static struct vp_table *
__validation_cycle(void)
{
	struct validation_thread *threads; /* array */
	unsigned int t;
	struct vp_table *vpt;
	int error;

	if (cache_prepare() != 0)
		return NULL;

	task_start();

	if (foreach_file(fortcfg.tal, ".tal", true, queue_tal, NULL) != 0)
		goto cancel;

	if (report_enable() != 0)
		goto cancel;

	threads = vthreads_create();

	for (t = 0; t < fortcfg.thread_pool.validation.max; t++) {
		error = pthread_create(&threads[t].id, NULL, claim_work,
		    &threads[t]);
		if (error)
			pr_panic("pthread_create(%u) failed: %s",
			    t, strerror(error));
	}

	for (t = 0; t < fortcfg.thread_pool.validation.max; t++) {
		error = pthread_join(threads[t].id, NULL);
		if (error)
			pr_panic("pthread_join(%u) failed: %s",
			    t, strerror(error));
	}

	vpt = task_stopped() ? NULL : vthreads_commit(threads);

//		// FIXME
//		stats_set_tal_vrps(thread->tal_file, "ipv4",
//		    vpt_vrp4_count(thread->db));
//		stats_set_tal_vrps(thread->tal_file, "ipv6",
//		    vpt_vrp6_count(thread->db));

	vthreads_destroy(threads);
	report_disable();
	task_stop();

	if (vpt && clean_and_export_vpt(vpt) != 0) {
		vpt_destroy(vpt);
		vpt = NULL;
	}

	cache_commit();

	return vpt;

cancel:
	task_stop();
	return NULL;
}

static double
get_runtime(time_t start, time_t finish)
{
	return (start != ((time_t) -1) && finish != ((time_t) -1))
	    ? difftime(finish, start)
	    : -1;
}

static int
validation_cycle(struct rtr_metadata *rtr)
{
	struct vp_table *vpt;
	time_t start, finish;

	start = time(NULL);
	vpt = __validation_cycle();
	finish = time(NULL);

	pr_inf("Validation cycle ended. VRPs %u RKs %u ASPAs %u Runtime %.0lf",
	    vpt_vrp_count(vpt), vpt_rk_count(vpt), vpt_aspa_count(vpt),
	    get_runtime(start, finish));

	if (rtr) {
		rtr->session = vpt_session(vpt);
		rtr->serial = vpt_serial(vpt);
	}

	vpt_destroy(vpt);
	return vpt ? 0 : EINVAL;
}

static int
fort_standalone(void)
{
	int error;

	pr_inf("Updating cache...");

	error = validation_cycle(NULL);
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

	error = validation_cycle(&rtr);
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

		error = validation_cycle(&rtr);
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

	/* DO NOT START ANY THREADS UNTIL WE'RE DONE fork()ING. */
	/* DO NOT INSTALL SIGNAL HANDLERS UNTIL WE'RE DONE DAEMONIZING. */
	/* Also: Daemonizing will close all file descriptors. */

	log_setup();

	verdict = handle_flags_config(argc, argv);
	if (verdict == IV_FAIL) {
		error = EINVAL;
		goto revert_log;
	}
	if (verdict == IV_DONE) {
		error = 0;
		goto revert_log;
	}

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
	}

	error = log_init();
	if (error)
		goto revert_daemon;

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

	fnstack_setup();

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
revert_log:
	log_teardown();
	return convert_to_result(error);
}
