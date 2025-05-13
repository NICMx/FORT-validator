#include <errno.h>

#include "cache.h"
#include "config.h"
#include "ext.h"
#include "hash.h"
#include "http.h"
#include "log.h"
#include "nid.h"
#include "output_printer.h"
#include "print_file.h"
#include "relax_ng.h"
#include "rtr/db/vrps.h"
#include "rtr/rtr.h"
#include "rsync.h"
#include "sig.h"
#include "task.h"
#include "thread_var.h"

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
	int error;
	bool changed;

	pr_op_info("Main loop: Starting...");

	error = rtr_start();
	if (error)
		return error;

	error = vrps_update(NULL);
	if (error) {
		pr_op_err("Main loop: Validation unsuccessful; results unusable.");
		return error;
	}

	rtr_notify();

	/*
	 * See issue #133.
	 * TODO (#50) Remove this message once the stats server is implemented.
	 */
	pr_op_warn("First validation cycle successfully ended, now you can connect your router(s)");

	do {
		pr_op_info("Main loop: Sleeping.");
		sleep(config_get_validation_interval());
		pr_op_info("Main loop: Time to work!");

		error = vrps_update(&changed);
		if (error == EINTR)
			break;
		if (error) {
			pr_op_debug("Main loop: %s", strerror(error));
			continue;
		}
		if (changed)
			rtr_notify();
	} while (true);

	rtr_stop();
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

	/* Initializations */
	/* (Do not start any threads until after rsync_setup() has forked.) */

	error = log_setup();
	if (error)
		goto just_quit;
	error = handle_flags_config(argc, argv);
	if (error)
		goto revert_log;

	rsync_setup(NULL, NULL); /* Fork rsync spawner ASAP */
	register_signal_handlers();

	error = thvar_init();
	if (error)
		goto revert_rsync;
	error = incidence_init();
	if (error)
		goto revert_rsync;
	error = nid_init();
	if (error)
		goto revert_rsync;
	error = extension_init();
	if (error)
		goto revert_nid;
	error = hash_setup();
	if (error)
		goto revert_nid;
	error = http_init();
	if (error)
		goto revert_hash;
	error = relax_ng_init();
	if (error)
		goto revert_http;
	error = vrps_init();
	if (error)
		goto revert_relax_ng;
	error = cache_setup();
	if (error)
		goto revert_vrps;
	error = output_setup();
	if (error)
		goto revert_vrps;
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
revert_vrps:
	vrps_destroy();
revert_relax_ng:
	relax_ng_cleanup();
revert_http:
	http_cleanup();
revert_hash:
	hash_teardown();
revert_nid:
	nid_destroy();
revert_rsync:
	rsync_teardown();
	free_rpki_config();
revert_log:
	log_teardown();
just_quit:
	return convert_to_result(error);
}
