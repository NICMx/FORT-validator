#include "clients.h"
#include "config.h"
#include "debug.h"
#include "extension.h"
#include "nid.h"
#include "thread_var.h"
#include "vrps.h"
#include "rsync/rsync.h"
#include "rtr/rtr.h"

static int
start_rtr_server(void)
{
	int error;

	error = deltas_db_init();
	if (error)
		goto end1;

	error = clients_db_init();
	if (error)
		goto end2;

	error = rtr_listen();
	rtr_cleanup(); /* TODO shouldn't this only happen on !error? */

	clients_db_destroy();
end2:	deltas_db_destroy();
end1:	return error;
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
		goto revert_rsync;

	error = perform_standalone_validation(NULL);
	if (error)
		goto revert_rsync;

	if (config_get_server_address() != NULL)
		error = start_rtr_server();
	/* Otherwise, no server requested. */

revert_rsync:
	rsync_destroy();
revert_config:
	free_rpki_config();
	return error;
}
