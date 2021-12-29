#include "config.h"
#include "extension.h"
#include "nid.h"
#include "thread_var.h"
#include "validation_run.h"
#include "http/http.h"
#include "rtr/rtr.h"
#include "rtr/db/vrps.h"
#include "xml/relax_ng.h"

static int
run_rtr_server(void)
{
	int error;

	error = rtr_start();
	if (error)
		return error;

	error = validation_run_first();
	if (!error)
		error = validation_run_cycle(); /* Usually loops forever */

	rtr_stop();
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
	error = nid_init();
	if (error)
		goto revert_config;
	error = extension_init();
	if (error)
		goto revert_nid;
	error = http_init();
	if (error)
		goto revert_nid;

	error = relax_ng_init();
	if (error)
		goto revert_http;
	error = vrps_init();
	if (error)
		goto revert_relax_ng;

	/* Do stuff */
	switch (config_get_mode()) {
	case STANDALONE:
		error = validation_run_first();
		break;
	case SERVER:
		error = run_rtr_server();
		break;
	}

	/* End */

	vrps_destroy();
revert_relax_ng:
	relax_ng_cleanup();
revert_http:
	http_cleanup();
revert_nid:
	nid_destroy();
revert_config:
	free_rpki_config();
revert_log:
	log_teardown();
just_quit:
	return convert_to_result(error);
}
