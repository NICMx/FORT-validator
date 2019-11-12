#include "clients.h"
#include "config.h"
#include "debug.h"
#include "extension.h"
#include "nid.h"
#include "thread_var.h"
#include "http/http.h"
#include "rtr/rtr.h"
#include "rtr/db/vrps.h"

static int
start_rtr_server(void)
{
	int error;

	error = vrps_init();
	if (error)
		goto just_quit;

	error = rtr_listen();

	vrps_destroy();
just_quit:
	return error;
}

int
__main(int argc, char **argv)
{
	int error;

	print_stack_trace_on_segfault();

	error = thvar_init();
	if (error)
		return error;
	error = incidence_init();
	if (error)
		return error;

	error = handle_flags_config(argc, argv);
	if (error)
		return error;

	error = nid_init();
	if (error)
		goto revert_config;
	error = extension_init();
	if (error)
		goto revert_nid;

	error = http_init();
	if (error)
		goto revert_nid;

	error = start_rtr_server();

	http_cleanup();
revert_nid:
	nid_destroy();
revert_config:
	free_rpki_config();
	return error;
}

int
main(int argc, char **argv)
{
	int error;

	log_setup();
	error = __main(argc, argv);
	log_teardown();

	return error;
}
