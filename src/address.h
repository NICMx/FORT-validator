#ifndef SRC_ADDRESS_H_
#define SRC_ADDRESS_H_

#include <netinet/in.h>

struct ipv4_prefix {
	struct in_addr addr;
	unsigned int len;
};

struct ipv6_prefix {
	struct in6_addr addr;
	unsigned int len;
};

int prefix4_decode(const char *, struct ipv4_prefix *);
int prefix6_decode(const char *, struct ipv6_prefix *);

int prefix_length_decode(const char *, unsigned int *, int);

int prefix4_validate (struct ipv4_prefix *);
int prefix6_validate (struct ipv6_prefix *);

#endif /* SRC_ADDRESS_H_ */
