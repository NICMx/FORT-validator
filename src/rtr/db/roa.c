#include "rtr/db/roa.h"

DEFINE_ARRAY_LIST_FUNCTIONS(v4_addresses, struct v4_address)
DEFINE_ARRAY_LIST_FUNCTIONS(v6_addresses, struct v6_address)

int
roa_create(uint32_t as, struct roa **_result)
{
	struct roa *result;

	result = malloc(sizeof(struct roa));
	if (result == NULL)
		return pr_enomem();

	result->as = as;
	v4_addresses_init(&result->addrs4);
	v6_addresses_init(&result->addrs6);

	*_result = result;
	return 0;
}

void
roa_destroy(struct roa *roa)
{
	v4_addresses_cleanup(&roa->addrs4, NULL);
	v6_addresses_cleanup(&roa->addrs6, NULL);
}

int
roa_add_v4(struct roa *roa, uint32_t as, struct ipv4_prefix const *prefix,
    uint8_t max_length)
{
	struct v4_address addr;

	if (roa->as != as) {
		return pr_err("ROA has more than one ASN. (%u and %u)",
		    roa->as, as);
	}

	addr.prefix = *prefix;
	addr.max_length = max_length;
	return v4_addresses_add(&roa->addrs4, &addr);
}

int
roa_add_v6(struct roa *roa, uint32_t as, struct ipv6_prefix const *prefix,
    uint8_t max_length)
{
	struct v6_address addr;

	if (roa->as != as) {
		return pr_err("ROA has more than one ASN. (%u and %u)",
		    roa->as, as);
	}

	addr.prefix = *prefix;
	addr.max_length = max_length;
	return v6_addresses_add(&roa->addrs6, &addr);
}
