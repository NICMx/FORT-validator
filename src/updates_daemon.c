#include "updates_daemon.h"

#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#include "csv.h"
#include "configuration.h"
#include "notify.h"

static void *
check_vrps_updates(void *param_void) {
	int error;
	bool updated;
	do {
		updated = false;
		error = csv_check_vrps_file(&updated);
		if (error) {
			warnx("Error while searching CSV updates, sleeping..");
			goto sleep;
		}
		if (updated)
			notify_clients();
sleep:
		sleep(config_get_vrps_check_interval());
	} while (true);

	return NULL;
}

int
updates_daemon_init(void) {
	pthread_t thread;
	errno = pthread_create(&thread, NULL, check_vrps_updates, NULL);
	if (errno) {
		warn("Could not spawn the update daemon thread");
		return errno;
	}
	pthread_detach(thread);
	return 0;
}
