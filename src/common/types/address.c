#include "common/types/address.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"

static void
init_quadrant(struct in6_addr *addr, unsigned int slot, uint32_t value)
{
	addr->s6_addr[slot    ] = (value >> 24)       ;
	addr->s6_addr[slot + 1] = (value >> 16) & 0xFF;
	addr->s6_addr[slot + 2] = (value >>  8) & 0xFF;
	addr->s6_addr[slot + 3] = (value      ) & 0xFF;
}

void
in6_addr_init(struct in6_addr *addr, uint32_t quadrant0, uint32_t quadrant1,
    uint32_t quadrant2, uint32_t quadrant3)
{
	init_quadrant(addr, 0, quadrant0);
	init_quadrant(addr, 4, quadrant1);
	init_quadrant(addr, 8, quadrant2);
	init_quadrant(addr, 12, quadrant3);
}

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

#define V6_QUADRANT_EDIT(addr, quadrant, op, value)			\
	addr->s6_addr[4 * quadrant    ] op (value >> 24)       ;	\
	addr->s6_addr[4 * quadrant + 1] op (value >> 16) & 0xFF;	\
	addr->s6_addr[4 * quadrant + 2] op (value >>  8) & 0xFF;	\
	addr->s6_addr[4 * quadrant + 3] op (value      ) & 0xFF;

/**
 * Same as `addr->s6_addr32[quadrant] = htonl(value)`.
 */
static void
addr6_set_quadrant(struct in6_addr *addr, unsigned int quadrant, uint32_t value)
{
	V6_QUADRANT_EDIT(addr, quadrant, =, value)
}

/**
 * Same as `addr->s6_addr32[quadrant] |= htonl(value)`.
 */
static void
addr6_or_quadrant(struct in6_addr *addr, unsigned int quadrant, uint32_t value)
{
	V6_QUADRANT_EDIT(addr, quadrant, |=, value)
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
		addr6_or_quadrant(result, 0, u32_suffix_mask(prefix_len));
		addr6_set_quadrant(result, 1, 0xFFFFFFFFu);
		addr6_set_quadrant(result, 2, 0xFFFFFFFFu);
		addr6_set_quadrant(result, 3, 0xFFFFFFFFu);
	} else if (prefix_len < 64) {
		addr6_or_quadrant(result, 1, u32_suffix_mask(prefix_len - 32));
		addr6_set_quadrant(result, 2, 0xFFFFFFFFu);
		addr6_set_quadrant(result, 3, 0xFFFFFFFFu);
	} else if (prefix_len < 96) {
		addr6_or_quadrant(result, 2, u32_suffix_mask(prefix_len - 64));
		addr6_set_quadrant(result, 3, 0xFFFFFFFFu);
	} else {
		addr6_or_quadrant(result, 3, u32_suffix_mask(prefix_len - 96));
	}
}

bool
addr6_equals(struct in6_addr const *a, struct in6_addr const *b)
{
	unsigned int i;
	for (i = 0; i < INET_ADDRSTRLEN; i++) {
		if (a->s6_addr[i] != b->s6_addr[i])
			return false;
	}
	return true;
}

bool
prefix4_equals(struct ipv4_prefix const *a, struct ipv4_prefix const *b)
{
	return (a->len == b->len) && (a->addr.s_addr == b->addr.s_addr);
}

bool
prefix6_equals(struct ipv6_prefix const *a, struct ipv6_prefix const *b)
{
	return (a->len == b->len) && addr6_equals(&a->addr, &b->addr);
}

static int
str2addr4(const char *addr, struct in_addr *dst)
{
	return (inet_pton(AF_INET, addr, dst) != 1) ? EINVAL : 0;
}

static int
str2addr6(const char *addr, struct in6_addr *dst)
{
	return (inet_pton(AF_INET6, addr, dst) != 1) ? EINVAL : 0;
}

int
prefix4_parse(const char *str, struct ipv4_prefix *result)
{
	int error;

	if (str == NULL)
		return pr_err("Can't parse NULL IPv4 prefix");

	error = str2addr4(str, &result->addr);
	if (error)
		return pr_err("Invalid IPv4 prefix '%s'", str);

	return 0;
}

int
prefix6_parse(const char *str, struct ipv6_prefix *result)
{
	int error;

	if (str == NULL)
		return pr_err("Can't parse NULL IPv6 prefix");

	error = str2addr6(str, &result->addr);
	if (error)
		return pr_err("Invalid IPv6 prefix '%s'", str);

	return 0;
}

int
prefix_length_parse(const char *text, uint8_t *dst, uint8_t max_value)
{
	unsigned long len;
	int error;

	if (text == NULL)
		return pr_err("Can't decode NULL prefix length");

	errno = 0;
	len = strtoul(text, NULL, 10);
	error = errno;
	if (error) {
		return pr_err("Invalid prefix length '%s': %s", text,
		    strerror(error));
	}
	/* An underflow or overflow will be considered here */
	if (max_value < len)
		return pr_err("Prefix length (%lu) is out of range (0-%u).",
		    len, max_value);

	*dst = (uint8_t) len;
	return 0;
}

int
ipv4_prefix_validate(struct ipv4_prefix *prefix)
{
	char buffer[INET_ADDRSTRLEN];

	if ((prefix->addr.s_addr & be32_suffix_mask(prefix->len)) != 0)
		return pr_err("IPv4 prefix %s/%u has enabled suffix bits.",
		    addr2str4(&prefix->addr, buffer), prefix->len);

	return 0;
}

int
ipv6_prefix_validate(struct ipv6_prefix *prefix)
{
	struct in6_addr suffix;
	char buffer[INET6_ADDRSTRLEN];
	unsigned int i;

	memset(&suffix, 0, sizeof(suffix));
	ipv6_suffix_mask(prefix->len, &suffix);

	for (i = 0; i < 16; i++)
		if (prefix->addr.s6_addr[i] & suffix.s6_addr[i])
			return pr_err("IPv6 prefix %s/%u has enabled suffix bits.",
			    addr2str6(&prefix->addr, buffer), prefix->len);

	return 0;
}

/*
 * Check if @son_addr is covered by @f_addr prefix of @f_len length
 */
bool
ipv4_covered(struct in_addr const *f_addr, uint8_t f_len,
    struct in_addr const *son_addr)
{
	return (son_addr->s_addr & ~be32_suffix_mask(f_len)) == f_addr->s_addr;
}

/*
 * Check if @son_addr is covered by @f_addr prefix of @f_len length
 */
bool
ipv6_covered(struct in6_addr const *f_addr, uint8_t f_len,
    struct in6_addr const *son_addr)
{
	struct in6_addr suffix;
	unsigned int i;

	memset(&suffix, 0, sizeof(suffix));
	ipv6_suffix_mask(f_len, &suffix);

	for (i = 0; i < 16; i++)
		if ((son_addr->s6_addr[i] & ~suffix.s6_addr[i]) !=
		    f_addr->s6_addr[i])
			return false;

	return true;
}

char const *
addr2str4(struct in_addr const *addr, char *buffer)
{
	return inet_ntop(AF_INET, addr, buffer, INET_ADDRSTRLEN);
}

char const *
addr2str6(struct in6_addr const *addr, char *buffer)
{
	return inet_ntop(AF_INET6, addr, buffer, INET6_ADDRSTRLEN);
}

/**
 * buffer must length INET6_ADDRSTRLEN.
 */
bool
sockaddr2str(struct sockaddr_storage *sockaddr, char *buffer)
{
	void *addr = NULL;
	char const *str;

	if (sockaddr == NULL) {
		strcpy(buffer, "(null)");
		return false;
	}

	switch (sockaddr->ss_family) {
	case AF_INET:
		addr = &((struct sockaddr_in *) sockaddr)->sin_addr;
		break;
	case AF_INET6:
		addr = &((struct sockaddr_in6 *) sockaddr)->sin6_addr;
		break;
	default:
		strcpy(buffer, "(protocol unknown)");
		return false;
	}

	str = inet_ntop(sockaddr->ss_family, addr, buffer, INET6_ADDRSTRLEN);
	if (str == NULL) {
		strcpy(buffer, "(unprintable address)");
		return false;
	}

	return true;
}
