#include "rtr/db/vrp.h"

#include <arpa/inet.h>

static void
print_flag(uint8_t flag)
{
	switch (flag) {
	case FLAG_WITHDRAWAL:
		printf("- DEL ");
		break;
	case FLAG_ANNOUNCEMENT:
		printf("- ADD ");
		break;
	default:
		printf("- (unknown)");
		break;
	}
}

int
vrp_print(struct vrp const *roa, void *arg)
{
	char buffer[INET6_ADDRSTRLEN];
	printf("- [ROA ASN:%u Prefix:%s/(%u-%u)]\n", roa->asn,
	    inet_ntop(roa->addr_fam, &roa->prefix, buffer, INET6_ADDRSTRLEN),
	    roa->prefix_length, roa->max_prefix_length);
	return 0;
}

int
delta_vrp_print(struct delta_vrp const *delta, void *arg)
{
	print_flag(delta->flags);
	return vrp_print(&delta->vrp, arg);
}

int
router_key_print(struct router_key const *rk, void *arg)
{
	printf("- [RK  ASN:%u]\n", rk->as);
	return 0;
}

int
delta_rk_print(struct delta_router_key const *delta, void *arg)
{
	print_flag(delta->flags);
	return router_key_print(&delta->router_key, arg);
}
