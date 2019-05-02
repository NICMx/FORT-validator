#include "clients.h"
#include "config.h"
#include "console_handler.h"
#include "debug.h"
#include "extension.h"
#include "nid.h"
#include "slurm_loader.h"
#include "thread_var.h"
#include "rsync/rsync.h"
#include "rtr/rtr.h"
#include "rtr/db/vrps.h"

static int
start_rtr_server(void)
{
	int error;

	error = vrps_init();
	if (error)
		goto just_quit;
	error = clients_db_init();
	if (error)
		goto revert_vrps;
	error = slurm_load();
	if (error)
		goto revert_clients;

	error = rtr_listen();

	slurm_cleanup();
revert_clients:
	clients_db_destroy();
revert_vrps:
	vrps_destroy();
just_quit:
	return error;
}

int
main(int argc, char **argv)
{
	int error;

	print_stack_trace_on_segfault();

	error = thvar_init();
	if (error)
		return error;

	error = handle_flags_config(argc, argv);
	if (error)
		return error;

	error = rsync_init();
	if (error)
		goto revert_config;
	error = nid_init();
	if (error)
		goto revert_rsync;
	error = extension_init();
	if (error)
		goto revert_nid;

	error = (config_get_server_address() != NULL)
	    ? start_rtr_server()
	    : validate_into_console();

revert_nid:
	nid_destroy();
revert_rsync:
	rsync_destroy();
revert_config:
	free_rpki_config();
	return error;
}
