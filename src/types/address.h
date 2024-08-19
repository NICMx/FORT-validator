#ifndef SRC_TYPES_ADDRESS_H_
#define SRC_TYPES_ADDRESS_H_

#include <netdb.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "asn1/asn1c/IPAddressRange.h"

struct ipv4_prefix {
	struct in_addr addr;
	uint8_t len;
};

struct ipv6_prefix {
	struct in6_addr addr;
	uint8_t len;
};

struct ipv4_range {
	struct in_addr min;
	struct in_addr max;
};

struct ipv6_range {
	struct in6_addr min;
	struct in6_addr max;
};

void in6_addr_init(struct in6_addr *, uint32_t, uint32_t, uint32_t, uint32_t);

uint32_t u32_suffix_mask(unsigned int);
void ipv6_suffix_mask(unsigned int, struct in6_addr *);

bool addr6_equals(struct in6_addr const *, struct in6_addr const *);

bool prefix4_equals(struct ipv4_prefix const *, struct ipv4_prefix const *);
bool prefix6_equals(struct ipv6_prefix const *, struct ipv6_prefix const *);

int prefix4_decode(IPAddress_t const *, struct ipv4_prefix *);
int prefix6_decode(IPAddress_t const *, struct ipv6_prefix *);
int range4_decode(IPAddressRange_t const *, struct ipv4_range *);
int range6_decode(IPAddressRange_t const *, struct ipv6_range *);

int prefix4_parse(const char *, struct ipv4_prefix *);
int prefix6_parse(const char *, struct ipv6_prefix *);
int prefix_length_parse(const char *, uint8_t *, uint8_t);

int ipv4_prefix_validate(struct ipv4_prefix *);
int ipv6_prefix_validate(struct ipv6_prefix *);

bool ipv4_covered(struct in_addr const *, uint8_t, struct in_addr const *);
bool ipv6_covered(struct in6_addr const *, uint8_t, struct in6_addr const *);

char const *addr2str4(struct in_addr const *, char *);
char const *addr2str6(struct in6_addr const *, char *);
bool sockaddr2str(struct sockaddr_storage *, char *buffer);

#endif /* SRC_TYPES_ADDRESS_H_ */
