#include "address.h"

#include <string.h>
#include <errno.h>
#include "log.h"

/**
 * Returns a mask you can use to extract the suffix bits of an address whose
 * prefix lengths @prefix_len.
 * For example: Suppose that your address is 192.0.2.0/24.
 * addr4_suffix_mask(24) returns 0.0.0.255.
 */
uint32_t
ipv4_suffix_mask(unsigned int prefix_len)
{
	return htonl(0xFFFFFFFFu >> prefix_len);
}

void
ipv6_suffix_mask(unsigned int prefix_len, struct in6_addr *result)
{
	if (prefix_len < 32) {
		result->s6_addr32[0] |= htonl(0xFFFFFFFFu >> prefix_len);
		result->s6_addr32[1] = 0xFFFFFFFFu;
		result->s6_addr32[2] = 0xFFFFFFFFu;
		result->s6_addr32[3] = 0xFFFFFFFFu;
	} else if (prefix_len < 64) {
		result->s6_addr32[1] |= htonl(0xFFFFFFFFu >> (prefix_len - 32));
		result->s6_addr32[2] = 0xFFFFFFFFu;
		result->s6_addr32[3] = 0xFFFFFFFFu;
	} else if (prefix_len < 96) {
		result->s6_addr32[2] |= htonl(0xFFFFFFFFu >> (prefix_len - 64));
		result->s6_addr32[3] = 0xFFFFFFFFu;
	} else {
		result->s6_addr32[3] |= htonl(0xFFFFFFFFu >> (prefix_len - 96));
	}
}

int
prefix4_decode(IPAddress2_t *str, struct ipv4_prefix *result)
{
	int len;

	if (str->size > 4) {
		pr_err("IPv4 address has too many octets. (%u)", str->size);
		return -EINVAL;
	}
	if (str->bits_unused < 0 || 7 < str->bits_unused) {
		pr_err("Bit string IPv4 address's unused bits count (%d) is out of range (0-7).",
		    str->bits_unused);
		return -EINVAL;
	}

	memset(&result->addr, 0, sizeof(result->addr));
	memcpy(&result->addr, str->buf, str->size);
	len = 8 * str->size - str->bits_unused;

	if (len < 0 || 32 < len) {
		pr_err("IPv4 prefix length (%d) is out of bounds (0-32).", len);
		return -EINVAL;
	}

	result->len = len;

	if ((result->addr.s_addr & ipv4_suffix_mask(result->len)) != 0) {
		pr_err("IPv4 prefix has enabled suffix bits.");
		return -EINVAL;
	}

	return 0;
}

int
prefix6_decode(IPAddress2_t *str, struct ipv6_prefix *result)
{
	struct in6_addr suffix;
	int len;

	if (str->size > 16) {
		pr_err("IPv6 address has too many octets. (%u)", str->size);
		return -EINVAL;
	}
	if (str->bits_unused < 0 || 7 < str->bits_unused) {
		pr_err("Bit string IPv6 address's unused bits count (%d) is out of range (0-7).",
		    str->bits_unused);
		return -EINVAL;
	}

	memset(&result->addr, 0, sizeof(result->addr));
	memcpy(&result->addr, str->buf, str->size);
	len = 8 * str->size - str->bits_unused;

	if (len < 0 || 128 < len) {
		pr_err("IPv6 prefix length (%u) is out of bounds (0-128).",
		    len);
		return -EINVAL;
	}

	result->len = len;

	memset(&suffix, 0, sizeof(suffix));
	ipv6_suffix_mask(result->len, &suffix);
	if (   (result->addr.s6_addr32[0] & suffix.s6_addr32[0])
	    || (result->addr.s6_addr32[1] & suffix.s6_addr32[1])
	    || (result->addr.s6_addr32[2] & suffix.s6_addr32[2])
	    || (result->addr.s6_addr32[3] & suffix.s6_addr32[3])) {
		pr_err("IPv6 prefix has enabled suffix bits.");
		return -EINVAL;
	}

	return 0;
}

int
range4_decode(IPAddressRange_t *input, struct ipv4_range *result)
{
	struct ipv4_prefix prefix;
	int error;

	error = prefix4_decode(&input->min, &prefix);
	if (error)
		return error;
	result->min = prefix.addr;

	error = prefix4_decode(&input->max, &prefix);
	if (error)
		return error;
	result->max.s_addr = prefix.addr.s_addr | ipv4_suffix_mask(prefix.len);

	return 0;
}

int
range6_decode(IPAddressRange_t *input, struct ipv6_range *result)
{
	struct ipv6_prefix prefix;
	int error;

	error = prefix6_decode(&input->min, &prefix);
	if (error)
		return error;
	result->min = prefix.addr;

	error = prefix6_decode(&input->max, &prefix);
	if (error)
		return error;
	result->max = prefix.addr;
	ipv6_suffix_mask(prefix.len, &result->max);

	return 0;
}

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
