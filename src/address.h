#ifndef SRC_ADDRESS_H_
#define SRC_ADDRESS_H_

#include <stdbool.h>
#include <netinet/in.h>
#include <libcmscodec/IPAddress2.h>
#include <libcmscodec/IPAddressRange.h>

struct ipv4_prefix {
	struct in_addr addr;
	unsigned int len;
};

struct ipv6_prefix {
	struct in6_addr addr;
	unsigned int len;
};

struct ipv4_range {
	struct in_addr min;
	struct in_addr max;
};

struct ipv6_range {
	struct in6_addr min;
	struct in6_addr max;
};

uint32_t ipv4_suffix_mask(unsigned int);
void ipv6_suffix_mask(unsigned int, struct in6_addr *);

int prefix4_decode(IPAddress2_t *, struct ipv4_prefix *);
int prefix6_decode(IPAddress2_t *, struct ipv6_prefix *);
int range4_decode(IPAddressRange_t *, struct ipv4_range *);
int range6_decode(IPAddressRange_t *, struct ipv6_range *);

bool prefix4_contains(const struct ipv4_prefix *, const struct ipv4_prefix *);
bool prefix6_contains(const struct ipv6_prefix *, const struct ipv6_prefix *);

#endif /* SRC_ADDRESS_H_ */
