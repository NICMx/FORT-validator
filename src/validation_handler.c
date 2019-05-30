#include "validation_handler.h"

#include <errno.h>
#include "log.h"
#include "thread_var.h"

int
vhandler_reset(struct validation_handler *handler)
{
	return (handler->reset != NULL) ? handler->reset(handler->arg) : 0;
}

static int
get_current_threads_handler(struct validation_handler const **result)
{
	struct validation *state;
	struct validation_handler const *handler;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;
	handler = validation_get_validation_handler(state);
	if (handler == NULL)
		return pr_crit("This thread lacks a validation handler.");

	*result = handler;
	return 0;
}

int
vhandler_handle_roa_v4(uint32_t as, struct ipv4_prefix const *prefix,
    uint8_t max_length)
{
	struct validation_handler const *handler;
	int error;

	error = get_current_threads_handler(&handler);
	if (error)
		return error;

	return (handler->handle_roa_v4 != NULL)
	    ? handler->handle_roa_v4(as, prefix, max_length, handler->arg)
	    : 0;
}

int
vhandler_handle_roa_v6(uint32_t as, struct ipv6_prefix const *prefix,
    uint8_t max_length)
{
	struct validation_handler const *handler;
	int error;

	error = get_current_threads_handler(&handler);
	if (error)
		return error;

	return (handler->handle_roa_v6 != NULL)
	    ? handler->handle_roa_v6(as, prefix, max_length, handler->arg)
	    : 0;
}
