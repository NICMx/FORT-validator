#include "rrdp_handler.h"

#include "thread_var.h"

static int
get_current_threads_handler(struct rrdp_handler const **result)
{
	struct validation *state;
	struct rrdp_handler const *handler;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	handler = validation_get_rrdp_handler(state);
	if (handler == NULL)
		pr_crit("This thread lacks an RRDP handler.");

	*result = handler;
	return 0;
}

enum rrdp_uri_cmp_result
rhandler_uri_cmp(char const *uri, char const *session_id, unsigned long serial)
{
	struct rrdp_handler const *handler;
	int error;

	error = get_current_threads_handler(&handler);
	if (error)
		return error;

	return (handler->uri_cmp != NULL)
	    ? handler->uri_cmp(uri, session_id, serial)
	    : RRDP_URI_NOTFOUND;
}

int
rhandler_uri_update(char const *uri, char const *session_id,
    unsigned long serial)
{
	struct rrdp_handler const *handler;
	int error;

	error = get_current_threads_handler(&handler);
	if (error)
		return error;

	return (handler->uri_update != NULL)
	    ? handler->uri_update(uri, session_id, serial)
	    : 0;
}

int
rhandler_uri_get_serial(char const *uri, unsigned long *serial)
{
	struct rrdp_handler const *handler;
	int error;

	error = get_current_threads_handler(&handler);
	if (error)
		return error;

	return (handler->uri_get_serial != NULL)
	    ? handler->uri_get_serial(uri, serial)
	    : 0;
}
