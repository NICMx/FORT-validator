#include "object/router_key.h"

#include <string.h>

void
router_key_init(struct router_key *key, unsigned char const *ski,
    uint32_t as, unsigned char const *spk)
{
	memcpy(key->ski, ski, RK_SKI_LEN);
	memcpy(key->spk, spk, RK_SPKI_LEN);
	key->as = as;
}
