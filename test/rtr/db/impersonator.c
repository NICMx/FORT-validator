#include "object/tal.h"

#include <check.h>

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
perform_standalone_validation(struct validation_handler *handler)
{
	ck_assert_int_eq(0, handler->reset(handler->arg));

	switch (iteration) {
	case 0:
		add_v4(handler, 0);
		add_v6(handler, 0);
		break;
	case 1:
		add_v4(handler, 0);
		add_v6(handler, 0);
		add_v4(handler, 1);
		add_v6(handler, 1);
		break;
	case 2:
		add_v4(handler, 1);
		add_v6(handler, 1);
		break;
	case 3:
		add_v4(handler, 0);
		add_v6(handler, 0);
		break;
	default:
		ck_abort_msg("perform_standalone_validation() was called too many times (%d).",
		    iteration);
	}
	if (handler->merge != NULL)
		handler->merge(handler->merge_arg, handler->arg);

	iteration++;
	return 0;
}
