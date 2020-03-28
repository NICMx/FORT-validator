#include <check.h>
#include "object/tal.h"

#include "address.c"

static unsigned char db_imp_ski[] = {
    0x0e, 0xe9, 0x6a, 0x8e, 0x2f, 0xac, 0x50, 0xce, 0x6c, 0x5f,
    0x93, 0x3e, 0xde, 0x6a, 0xa7, 0x80, 0xa6, 0x85, 0x0e, 0x31 };

static unsigned char db_imp_spk[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xfa, 0xb9, 0x12,
    0x2d, 0x79, 0x4f, 0xa4, 0xbf, 0xe6, 0xf8, 0xbe, 0xc2, 0x7c,
    0x27, 0xca, 0xae, 0xfd, 0x45, 0x1e, 0xb3, 0x39, 0xe4, 0x5b,
    0x08, 0x73, 0xc7, 0xcc, 0x96, 0x78, 0xc7, 0x13, 0xa6, 0x39,
    0x9d, 0x3b, 0x82, 0x9f, 0x75, 0x20, 0x59, 0xf0, 0x95, 0xea,
    0xc6, 0x2e, 0x19, 0x46, 0x73, 0x3d, 0x9d, 0x04, 0xcb, 0xa0,
    0x2f, 0x7b, 0x39, 0x9f, 0x70, 0x42, 0xd4, 0x07, 0xce, 0xde,
    0x04 };

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

static void
add_rk(struct validation_handler *handler, uint32_t as)
{
	ck_assert_int_eq(0, handler->handle_router_key(db_imp_ski, as,
	    db_imp_spk, handler->arg));
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
		add_rk(&handler, 0);
		break;
	case 1:
		add_v4(&handler, 0);
		add_v6(&handler, 0);
		add_rk(&handler, 0);
		add_v4(&handler, 1);
		add_v6(&handler, 1);
		add_rk(&handler, 1);
		break;
	case 2:
		add_v4(&handler, 1);
		add_v6(&handler, 1);
		add_rk(&handler, 1);
		break;
	case 3:
		add_v4(&handler, 0);
		add_v6(&handler, 0);
		add_rk(&handler, 0);
		break;
	default:
		ck_abort_msg("perform_standalone_validation() was called too many times (%d).",
		    iteration);
	}

	iteration++;
	return 0;
}
