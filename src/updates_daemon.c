#include "updates_daemon.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#include "config.h"
#include "notify.h"
#include "object/tal.h"
#include "rtr/db/vrps.h"

static pthread_t thread;

static int
__reset(void *arg)
{
	return forthandler_reset(arg);
}

static int
__traverse_down(struct rfc5280_name *subject_name, void *arg)
{
	return forthandler_go_down(arg, subject_name);
}

static int
__traverse_up(void *arg)
{
	return forthandler_go_up(arg);
}

int
__handle_roa_v4(uint32_t as, struct ipv4_prefix const *prefix,
    uint8_t max_length, void *arg)
{
	return forthandler_handle_roa_v4(arg, as, prefix, max_length);
}

int
__handle_roa_v6(uint32_t as, struct ipv6_prefix const * prefix,
    uint8_t max_length, void *arg)
{
	return forthandler_handle_roa_v6(arg, as, prefix, max_length);
}

static void *
check_vrps_updates(void *param_void)
{
	struct validation_handler validation_handler;
	struct roa_tree *old_tree;
	struct deltas *deltas;
	int error;

	validation_handler.reset = __reset;
	validation_handler.traverse_down = __traverse_down;
	validation_handler.traverse_up = __traverse_up;
	validation_handler.handle_roa_v4 = __handle_roa_v4;
	validation_handler.handle_roa_v6 = __handle_roa_v6;
	old_tree = NULL;

	do {
		validation_handler.arg = roa_tree_create();
		if (validation_handler.arg == NULL) {
			pr_err("Memory allocation failed. Cannot validate. Sleeping...");
			goto sleep;
		}

		error = perform_standalone_validation(&validation_handler);
		if (error) {
			roa_tree_put(validation_handler.arg);
			pr_err("Validation failed (error code %d). Cannot udpate the ROA database. Sleeping...",
			    error);
			goto sleep;
		}

		if (old_tree == NULL) {
			error = vrps_update(validation_handler.arg, NULL);
			if (error) {
				roa_tree_put(validation_handler.arg);
				pr_err("Error code %d while trying to update the ROA database. Sleeping...",
				    error);
			} else {
				old_tree = validation_handler.arg;
			}
			goto sleep;
		}

		error = compute_deltas(old_tree, validation_handler.arg, &deltas);
		if (error) {
			roa_tree_put(validation_handler.arg);
			pr_err("Something went wrong while trying to compute the deltas. (error code %d.) Cannot update the ROA database. Sleeping...",
			    error);
			goto sleep;
		}

		if (deltas_is_empty(deltas)) {
			roa_tree_put(validation_handler.arg);
			deltas_destroy(deltas);
			pr_debug("No changes. Sleeping...");
			goto sleep;
		}

		error = vrps_update(validation_handler.arg, deltas);
		if (error) {
			roa_tree_put(validation_handler.arg);
			deltas_destroy(deltas);
			pr_err("Error code %d while trying to store the deltas in the database. Cannot update the ROA database. Sleeping...",
			    error);
			goto sleep;
		}

		old_tree = validation_handler.arg;
		notify_clients();
		pr_debug("Database updated successfully. Sleeping...");

sleep:
		sleep(config_get_vrps_check_interval());
	} while (true);

	return NULL;
}

int
updates_daemon_start(void)
{
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	errno = pthread_create(&thread, NULL, check_vrps_updates, NULL);
	pthread_attr_destroy(&attr);
	if (errno)
		return -pr_errno(errno,
		    "Could not spawn the update daemon thread");

	return 0;
}

void
updates_daemon_destroy(void)
{
	void *ptr = NULL;
	pthread_cancel(thread);
	pthread_join(thread, &ptr);
}
