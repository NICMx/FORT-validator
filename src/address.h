#ifndef SRC_ADDRESS_H_
#define SRC_ADDRESS_H_

#include <stdbool.h>
#include <netinet/in.h>

struct ipv4_prefix {
	struct in_addr addr;
	int len;
};

struct ipv6_prefix {
	struct in6_addr addr;
	int len;
};

bool prefix4_contains(const struct ipv4_prefix *, const struct ipv4_prefix *);
bool prefix6_contains(const struct ipv6_prefix *, const struct ipv6_prefix *);

#endif /* SRC_ADDRESS_H_ */
