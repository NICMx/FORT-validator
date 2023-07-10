#include "validation_handler.h"

#include <errno.h>
#include "log.h"
#include "thread_var.h"

/*
 * Never returns NULL by contract.
 */
static struct validation_handler const *
get_current_threads_handler(void)
{
	struct validation_handler const *handler;

	handler = validation_get_validation_handler(state_retrieve());
	if (handler == NULL)
		pr_crit("This thread lacks a validation handler.");

	return handler;
}

int
vhandler_handle_roa_v4(uint32_t as, struct ipv4_prefix const *prefix,
    uint8_t max_length)
{
	struct validation_handler const *handler;

	handler = get_current_threads_handler();

	return (handler->handle_roa_v4 != NULL)
	    ? handler->handle_roa_v4(as, prefix, max_length, handler->arg)
	    : 0;
}

int
vhandler_handle_roa_v6(uint32_t as, struct ipv6_prefix const *prefix,
    uint8_t max_length)
{
	struct validation_handler const *handler;

	handler = get_current_threads_handler();

	return (handler->handle_roa_v6 != NULL)
	    ? handler->handle_roa_v6(as, prefix, max_length, handler->arg)
	    : 0;
}

int
vhandler_handle_router_key(unsigned char const *ski,
    struct asn_range const *asns, unsigned char const *spk)
{
	struct validation_handler const *handler;

	handler = get_current_threads_handler();

	return (handler->handle_router_key != NULL)
	    ? handler->handle_router_key(ski, asns, spk, handler->arg)
	    : 0;
}
