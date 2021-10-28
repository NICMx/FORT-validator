#include "types/delta.h"

#include <stdio.h>

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
delta_vrp_print(struct delta_vrp const *delta, void *arg)
{
	print_flag(delta->flags);
	return vrp_print(&delta->vrp, arg);
}

int
delta_rk_print(struct delta_router_key const *delta, void *arg)
{
	print_flag(delta->flags);
	return router_key_print(&delta->router_key, arg);
}
