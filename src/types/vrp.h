#ifndef SRC_TYPES_VRP_H_
#define SRC_TYPES_VRP_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * Stands for "Validated ROA Payload." Seemingly defined earliest by RFC 6811.
 * It's one of those "192.0.2.0/24-28 => AS1234" things. Can also be IPv6.
 */
struct vrp {
	uint32_t asn;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} prefix;
	uint8_t prefix_length;
	uint8_t max_prefix_length;
	uint8_t addr_fam;
};

bool vrp_equals(struct vrp const *, struct vrp const *);
bool vrp_prefix_cov(struct vrp const *, struct vrp const *);
int vrp_print(struct vrp const *, void *);

#endif /* SRC_TYPES_VRP_H_ */
