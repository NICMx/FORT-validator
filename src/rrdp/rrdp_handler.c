#include "rrdp_handler.h"

#include "thread_var.h"

#define CALL_HANDLER_FUNC(func_name, func_call)				\
	struct rrdp_handler const *handler;				\
	int error;							\
									\
	error = get_current_threads_handler(&handler);			\
	if (error)							\
		return error;						\
									\
	return (handler->func_name != NULL)				\
	    ? handler->func_call					\
	    : 0;

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

rrdp_uri_cmp_result_t
rhandler_uri_cmp(char const *uri, char const *session_id, unsigned long serial)
{
	CALL_HANDLER_FUNC(uri_cmp, uri_cmp(uri, session_id, serial))
}

int
rhandler_uri_update(char const *uri, char const *session_id,
    unsigned long serial)
{
	CALL_HANDLER_FUNC(uri_update, uri_update(uri, session_id, serial))
}

int
rhandler_uri_get_serial(char const *uri, unsigned long *serial)
{
	CALL_HANDLER_FUNC(uri_get_serial, uri_get_serial(uri, serial))
}

int
rhandler_uri_get_last_update(char const *uri, long *serial)
{
	CALL_HANDLER_FUNC(uri_get_last_update, uri_get_last_update(uri, serial))
}

int
rhandler_uri_set_last_update(char const *uri)
{
	CALL_HANDLER_FUNC(uri_set_last_update, uri_set_last_update(uri))
}
