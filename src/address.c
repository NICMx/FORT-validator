#include "address.h"

#include <string.h>

bool
prefix4_contains(const struct ipv4_prefix *a, const struct ipv4_prefix *b)
{
	uint32_t maskbits;
	uint32_t a_bits;
	uint32_t b_bits;

	if (a->len > b->len)
		return false;

	maskbits = ((uint64_t) 0xffffffffU) << (32 - a->len);
	a_bits = ntohl(a->addr.s_addr) & maskbits;
	b_bits = ntohl(b->addr.s_addr) & maskbits;

	return a_bits == b_bits;
}

bool
prefix6_contains(const struct ipv6_prefix *a, const struct ipv6_prefix *b)
{
	struct in6_addr a2;
	struct in6_addr b2;
	unsigned int quadrant;
	uint32_t mask;
	unsigned int i;

	if (a->len > b->len)
		return false;

	memcpy(&a2, &a->addr, sizeof(a2));
	memcpy(&b2, &b->addr, sizeof(b2));

	/* Zeroize the suffixes of a2 and b2 */
	quadrant = a->len >> 5; /* ">> 5" is the same as "/ 32" */
	if (quadrant > 3)
		quadrant = 3;
	mask = ((uint64_t) 0xffffffffU) << (32 - (a->len & 0x1f));
	a2.s6_addr32[quadrant] = htonl(ntohl(a2.s6_addr32[quadrant]) & mask);
	b2.s6_addr32[quadrant] = htonl(ntohl(b2.s6_addr32[quadrant]) & mask);
	for (i = quadrant + 1; i < 4; i++) {
		a2.s6_addr32[i] = 0;
		b2.s6_addr32[i] = 0;
	}

	/* Finally compare */
	return memcmp(&a2, &b2, sizeof(a2)) == 0;
}
