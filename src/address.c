#include "address.h"

#include <string.h>
#include <errno.h>
#include <arpa/inet.h> /* inet_ntop */
#include "log.h"
#include "thread_var.h"

/*
 * Returns a mask you can use to extract the suffix bits of a 32-bit unsigned
 * number whose prefix lengths @prefix_len.
 * For example: Suppose that your number is 192.0.2.0/24.
 * u32_suffix_mask(24) returns 0.0.0.255.
 *
 * The result is in host byte order.
 */
uint32_t
u32_suffix_mask(unsigned int prefix_len)
{
	/* `a >> 32` is undefined if `a` is 32 bits. */
	return (prefix_len < 32) ? (0xFFFFFFFFu >> prefix_len) : 0;
}

/**
 * Same as u32_suffix_mask(), except the result is in network byte order
 * ("be", for "big endian").
 */
uint32_t
be32_suffix_mask(unsigned int prefix_len)
{
	return htonl(u32_suffix_mask(prefix_len));
}

/**
 * Enables all the suffix bits of @result (assuming its prefix length is
 * @prefix_len).
 * @result's prefix bits will not be modified.
 */
void
ipv6_suffix_mask(unsigned int prefix_len, struct in6_addr *result)
{
	if (prefix_len < 32) {
		result->s6_addr32[0] |= be32_suffix_mask(prefix_len);
		result->s6_addr32[1] = 0xFFFFFFFFu;
		result->s6_addr32[2] = 0xFFFFFFFFu;
		result->s6_addr32[3] = 0xFFFFFFFFu;
	} else if (prefix_len < 64) {
		result->s6_addr32[1] |= be32_suffix_mask(prefix_len - 32);
		result->s6_addr32[2] = 0xFFFFFFFFu;
		result->s6_addr32[3] = 0xFFFFFFFFu;
	} else if (prefix_len < 96) {
		result->s6_addr32[2] |= be32_suffix_mask(prefix_len - 64);
		result->s6_addr32[3] = 0xFFFFFFFFu;
	} else {
		result->s6_addr32[3] |= be32_suffix_mask(prefix_len - 96);
	}
}

/**
 * Translates an `IPAddress2_t` to its equivalent `struct ipv4_prefix`.
 */
int
prefix4_decode(IPAddress2_t *str, struct ipv4_prefix *result)
{
	int len;

	if (str->size > 4) {
		return pr_err("IPv4 address has too many octets. (%zu)",
		    str->size);
	}
	if (str->bits_unused < 0 || 7 < str->bits_unused) {
		return pr_err("Bit string IPv4 address's unused bits count (%d) is out of range (0-7).",
		    str->bits_unused);
	}

	memset(&result->addr, 0, sizeof(result->addr));
	memcpy(&result->addr, str->buf, str->size);
	len = 8 * str->size - str->bits_unused;

	if (len < 0 || 32 < len) {
		return pr_err("IPv4 prefix length (%d) is out of bounds (0-32).",
		    len);
	}

	result->len = len;

	if ((result->addr.s_addr & be32_suffix_mask(result->len)) != 0) {
		return pr_err("IPv4 prefix '%s/%u' has enabled suffix bits.",
		    v4addr2str(&result->addr), result->len);
	}

	return 0;
}

/**
 * Translates an `IPAddress2_t` to its equivalent `struct ipv6_prefix`.
 */
int
prefix6_decode(IPAddress2_t *str, struct ipv6_prefix *result)
{
	struct in6_addr suffix;
	int len;

	if (str->size > 16) {
		return pr_err("IPv6 address has too many octets. (%zu)",
		    str->size);
	}
	if (str->bits_unused < 0 || 7 < str->bits_unused) {
		return pr_err("Bit string IPv6 address's unused bits count (%d) is out of range (0-7).",
		    str->bits_unused);
	}

	memset(&result->addr, 0, sizeof(result->addr));
	memcpy(&result->addr, str->buf, str->size);
	len = 8 * str->size - str->bits_unused;

	if (len < 0 || 128 < len) {
		return pr_err("IPv6 prefix length (%d) is out of bounds (0-128).",
		    len);
	}

	result->len = len;

	memset(&suffix, 0, sizeof(suffix));
	ipv6_suffix_mask(result->len, &suffix);
	if (   (result->addr.s6_addr32[0] & suffix.s6_addr32[0])
	    || (result->addr.s6_addr32[1] & suffix.s6_addr32[1])
	    || (result->addr.s6_addr32[2] & suffix.s6_addr32[2])
	    || (result->addr.s6_addr32[3] & suffix.s6_addr32[3])) {
		return pr_err("IPv6 prefix '%s/%u' has enabled suffix bits.",
		    v6addr2str(&result->addr), result->len);
	}

	return 0;
}

static int
check_order4(struct ipv4_range *result)
{
	if (ntohl(result->min.s_addr) > ntohl(result->max.s_addr)) {
		return pr_err("The IPv4 range '%s-%s' is inverted.",
		    v4addr2str(&result->min), v4addr2str2(&result->max));
	}

	return 0;
}

/**
 * If @range could have been encoded as a prefix, this function errors.
 *
 * rfc3779#section-2.2.3.7
 */
static int
check_encoding4(struct ipv4_range *range)
{
	const uint32_t MIN = ntohl(range->min.s_addr);
	const uint32_t MAX = ntohl(range->max.s_addr);
	uint32_t mask;

	for (mask = 0x80000000u; mask != 0; mask >>= 1)
		if ((MIN & mask) != (MAX & mask))
			break;

	for (; mask != 0; mask >>= 1)
		if (((MIN & mask) != 0) || ((MAX & mask) == 0))
			return 0;

	return pr_err("IPAddressRange '%s-%s' is a range, but should have been encoded as a prefix.",
	    v4addr2str(&range->min), v4addr2str2(&range->max));
}

/**
 * Translates an `IPAddressRange_t` to its equivalent `struct ipv4_range`.
 */
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
	result->max.s_addr = prefix.addr.s_addr | be32_suffix_mask(prefix.len);

	error = check_order4(result);
	if (error)
		return error;

	return check_encoding4(result);
}

static int
check_order6(struct ipv6_range *result)
{
	uint32_t min;
	uint32_t max;
	unsigned int quadrant;

	for (quadrant = 0; quadrant < 4; quadrant++) {
		min = ntohl(result->min.s6_addr32[quadrant]);
		max = ntohl(result->max.s6_addr32[quadrant]);
		if (min > max) {
			return pr_err("The IPv6 range '%s-%s' is inverted.",
			    v6addr2str(&result->min),
			    v6addr2str2(&result->max));
		} else if (min < max) {
			return 0; /* result->min < result->max */
		}
	}

	return 0; /* result->min == result->max */
}

static int
pr_bad_encoding(struct ipv6_range *range)
{
	return pr_err("IPAddressRange %s-%s is a range, but should have been encoded as a prefix.",
	    v6addr2str(&range->min), v6addr2str2(&range->max));
}

static int
__check_encoding6(struct ipv6_range *range, unsigned int quadrant,
    uint32_t mask)
{
	uint32_t min;
	uint32_t max;

	for (; quadrant < 4; quadrant++) {
		min = ntohl(range->min.s6_addr32[quadrant]);
		max = ntohl(range->max.s6_addr32[quadrant]);
		for (; mask != 0; mask >>= 1)
			if (((min & mask) != 0) || ((max & mask) == 0))
				return 0;
		mask = 0x80000000u;
	}

	return pr_bad_encoding(range);
}

static int
check_encoding6(struct ipv6_range *range)
{
	uint32_t min;
	uint32_t max;
	unsigned int quadrant;
	uint32_t mask;

	for (quadrant = 0; quadrant < 4; quadrant++) {
		min = ntohl(range->min.s6_addr32[quadrant]);
		max = ntohl(range->max.s6_addr32[quadrant]);
		for (mask = 0x80000000u; mask != 0; mask >>= 1)
			if ((min & mask) != (max & mask))
				return __check_encoding6(range, quadrant, mask);
	}

	return pr_bad_encoding(range);
}

/**
 * Translates an `IPAddressRange_t` to its equivalent `struct ipv6_range`.
 */
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

	error = check_order6(result);
	if (error)
		return error;

	return check_encoding6(result);
}
