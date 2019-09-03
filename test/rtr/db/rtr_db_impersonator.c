#include <check.h>
#include "object/tal.h"

#include "address.c"

static int iteration = 0;

static void
add_v4(struct validation_handler *handler, uint32_t as)
{
	struct ipv4_prefix prefix;
	prefix.addr.s_addr = htonl(0xC0000200);
	prefix.len = 24;
	ck_assert_int_eq(0, handler->handle_roa_v4(as, &prefix, 32,
	    handler->arg));
}

static void
add_v6(struct validation_handler *handler, uint32_t as)
{
	struct ipv6_prefix prefix;
	in6_addr_init(&prefix.addr, 0x20010DB8u, 0, 0, 0);
	prefix.len = 96;
	ck_assert_int_eq(0, handler->handle_roa_v6(as, &prefix, 120,
	    handler->arg));
}

int
__handle_roa_v4(uint32_t as, struct ipv4_prefix const *prefix,
    uint8_t max_length, void *arg)
{
	return rtrhandler_handle_roa_v4(arg, as, prefix, max_length);
}

int
__handle_roa_v6(uint32_t as, struct ipv6_prefix const * prefix,
    uint8_t max_length, void *arg)
{
	return rtrhandler_handle_roa_v6(arg, as, prefix, max_length);
}

int
__handle_router_key(unsigned char const *ski, uint32_t as,
    unsigned char const *spk, void *arg)
{
	return rtrhandler_handle_router_key(arg, ski, as, spk);
}

int
perform_standalone_validation(struct db_table *table)
{
	struct validation_handler handler;

	handler.handle_roa_v4 = __handle_roa_v4;
	handler.handle_roa_v6 = __handle_roa_v6;
	handler.handle_router_key = __handle_router_key;
	handler.arg = table;

	switch (iteration) {
	case 0:
		add_v4(&handler, 0);
		add_v6(&handler, 0);
		break;
	case 1:
		add_v4(&handler, 0);
		add_v6(&handler, 0);
		add_v4(&handler, 1);
		add_v6(&handler, 1);
		break;
	case 2:
		add_v4(&handler, 1);
		add_v6(&handler, 1);
		break;
	case 3:
		add_v4(&handler, 0);
		add_v6(&handler, 0);
		break;
	default:
		ck_abort_msg("perform_standalone_validation() was called too many times (%d).",
		    iteration);
	}

	iteration++;
	return 0;
}

void
terminate_standalone_validation(void)
{
	/* Nothing, no threads to join */
}
