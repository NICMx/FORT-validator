#include "types/router_key.h"

#include <stdio.h>
#include <string.h>

void
router_key_init(struct router_key *key, unsigned char const *ski,
    uint32_t as, unsigned char const *spk)
{
	memcpy(key->ski, ski, RK_SKI_LEN);
	memcpy(key->spk, spk, RK_SPKI_LEN);
	key->as = as;
}

int
router_key_print(struct router_key const *rk, void *arg)
{
	printf("- [RK  ASN:%u]\n", rk->as);
	return 0;
}
