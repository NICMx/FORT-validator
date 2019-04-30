#ifndef SRC_RTR_DB_ROA_H_
#define SRC_RTR_DB_ROA_H_

#include "address.h"
#include "data_structure/array_list.h"

struct v4_address {
	struct ipv4_prefix prefix;
	uint8_t max_length;
};

struct v6_address {
	struct ipv6_prefix prefix;
	uint8_t max_length;
};

DEFINE_ARRAY_LIST_STRUCT(v4_addresses, struct v4_address);
DEFINE_ARRAY_LIST_STRUCT(v6_addresses, struct v6_address);

struct roa {
	uint32_t as;
	struct v4_addresses addrs4;
	struct v6_addresses addrs6;
};

int roa_create(uint32_t, struct roa **);
void roa_destroy(struct roa *);

int roa_add_v4(struct roa *, uint32_t, struct ipv4_prefix const *, uint8_t);
int roa_add_v6(struct roa *, uint32_t, struct ipv6_prefix const *, uint8_t);

#endif /* SRC_RTR_DB_ROA_H_ */
