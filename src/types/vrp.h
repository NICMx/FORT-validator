#ifndef SRC_TYPES_VRP_H_
#define SRC_TYPES_VRP_H_

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

/*
 * A ROA.
 *
 * I think it's called "VRP" ("Validated ROA Payload") because it was originally
 * meant to represent an already validated ROA, and used exclusively by the RTR
 * code. But it doesn't matter anymore.
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

typedef int (*vrp_foreach_cb)(struct vrp const *, void *);

bool vrp_equals(struct vrp const *, struct vrp const *);
bool vrp_prefix_cov(struct vrp const *, struct vrp const *);
int vrp_print(struct vrp const *, void *);

#endif /* SRC_TYPES_VRP_H_ */
