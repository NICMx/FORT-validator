#include "validator/asn1/decode.h"

#include "common/log.h"
#include "validator/asn1/asn1c/ber_decoder.h"

/* Decoded BER data */
struct ber_data {
	const unsigned char *src;
	size_t src_size;
	size_t consumed;
};

static int
validate(asn_TYPE_descriptor_t const *descriptor, void *result, bool log)
{
	char errmsg[256];
	size_t errlen;

	/* The lib's inbuilt validations. (Probably not much.) */
	errlen = sizeof(errmsg);
	if (asn_check_constraints(descriptor, result, errmsg, &errlen) < 0) {
		if (log)
			pr_err("Error validating ASN.1 object: %s", errmsg);
		return EINVAL;
	}

	return 0;
}

int
asn1_decode(const void *buffer, size_t buffer_size,
    asn_TYPE_descriptor_t const *descriptor, void **result, bool log)
{
	asn_dec_rval_t rval;
	int error;

	*result = NULL;

	rval = ber_decode(descriptor, result, buffer, buffer_size);
	if (rval.code != RC_OK) {
		/* Must free partial object according to API contracts. */
		ASN_STRUCT_FREE(*descriptor, *result);
		/* We expect the data to be complete; RC_WMORE is an error. */
		if (log)
			pr_err("Error '%u' decoding ASN.1 object around byte %zu",
			    rval.code, rval.consumed);
		return EINVAL;
	}

	error = validate(descriptor, *result, log);
	if (error) {
		ASN_STRUCT_FREE(*descriptor, *result);
		return error;
	}

	return 0;
}

int
asn1_decode_any(ANY_t *any, asn_TYPE_descriptor_t const *descriptor,
    void **result, bool log)
{
	return (any != NULL)
	    ? asn1_decode(any->buf, any->size, descriptor, result, log)
	    : pr_err("ANY '%s' is NULL.", descriptor->name);
}

int
asn1_decode_octet_string(OCTET_STRING_t *string,
    asn_TYPE_descriptor_t const *descriptor, void **result, bool log)
{
	return (string != NULL)
	    ? asn1_decode(string->buf, string->size, descriptor, result, log)
	    : pr_err("Octet String '%s' is NULL.", descriptor->name);
}

/*
 * TODO (next iteration) There's no need to load the entire file into memory.
 * ber_decode() can take an incomplete buffer, in which case it returns
 * RC_WMORE.
 */
int
asn1_decode_fc(struct file_contents *fc,
    asn_TYPE_descriptor_t const *descriptor, void **result, bool log)
{
	return asn1_decode(fc->buf, fc->buflen, descriptor, result, log);
}

/**
 * Translates an `IPAddress_t` to its equivalent `struct ipv4_prefix`.
 */
int
prefix4_decode(IPAddress_t const *str, struct ipv4_prefix *result)
{
	char buf[INET_ADDRSTRLEN];
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
		    addr2str4(&result->addr, buf), result->len);
	}

	return 0;
}

/**
 * This is the same as `ntohl(addr->s6_addr32[quadrant])`.
 *
 * So why does it exist? Because s6_addr32 is not portable.
 *
 * Never use s6_addr16 nor s6_addr32.
 */
static uint32_t
addr6_get_quadrant(struct in6_addr *addr, unsigned int quadrant)
{
	return (((unsigned int) addr->s6_addr[4 * quadrant    ]) << 24)
	     | (((unsigned int) addr->s6_addr[4 * quadrant + 1]) << 16)
	     | (((unsigned int) addr->s6_addr[4 * quadrant + 2]) <<  8)
	     | (((unsigned int) addr->s6_addr[4 * quadrant + 3])      );
}

/**
 * Returns true if @a1 and @a2 have at least one enabled bit in common,
 * false otherwise.
 */
static bool
addr6_bitwise_and(struct in6_addr *a1, struct in6_addr *a2)
{
	unsigned int i;

	for (i = 0; i < 16; i++)
		if ((a1->s6_addr[i] & a2->s6_addr[i]) != 0)
			return true;

	return false;
}

/**
 * Translates an `IPAddress_t` to its equivalent `struct ipv6_prefix`.
 */
int
prefix6_decode(IPAddress_t const *str, struct ipv6_prefix *result)
{
	struct in6_addr suffix;
	char buf[INET6_ADDRSTRLEN];
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
	if (addr6_bitwise_and(&result->addr, &suffix)) {
		return pr_err("IPv6 prefix '%s/%u' has enabled suffix bits.",
		    addr2str6(&result->addr, buf), result->len);
	}

	return 0;
}

static int
check_order4(struct ipv4_range *result)
{
	char buf1[INET_ADDRSTRLEN];
	char buf2[INET_ADDRSTRLEN];

	if (ntohl(result->min.s_addr) > ntohl(result->max.s_addr)) {
		return pr_err("The IPv4 range '%s-%s' is inverted.",
		    addr2str4(&result->min, buf1),
		    addr2str4(&result->max, buf2));
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
	char buf1[INET_ADDRSTRLEN];
	char buf2[INET_ADDRSTRLEN];
	const uint32_t min = ntohl(range->min.s_addr);
	const uint32_t max = ntohl(range->max.s_addr);
	uint32_t mask;

	for (mask = 0x80000000u; mask != 0; mask >>= 1)
		if ((min & mask) != (max & mask))
			break;

	for (; mask != 0; mask >>= 1)
		if (((min & mask) != 0) || ((max & mask) == 0))
			return 0;

	return pr_err("IPAddressRange '%s-%s' is a range, but should have been encoded as a prefix.",
	    addr2str4(&range->min, buf1), addr2str4(&range->max, buf2));
}

/**
 * Translates an `IPAddressRange_t` to its equivalent `struct ipv4_range`.
 */
int
range4_decode(IPAddressRange_t const *input, struct ipv4_range *result)
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
	char buf1[INET6_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];

	for (quadrant = 0; quadrant < 4; quadrant++) {
		min = addr6_get_quadrant(&result->min, quadrant);
		max = addr6_get_quadrant(&result->max, quadrant);
		if (min > max) {
			return pr_err("The IPv6 range '%s-%s' is inverted.",
			    addr2str6(&result->min, buf1),
			    addr2str6(&result->max, buf2));
		} else if (min < max) {
			return 0; /* result->min < result->max */
		}
	}

	return 0; /* result->min == result->max */
}

static int
pr_bad_encoding(struct ipv6_range *range)
{
	char buf1[INET6_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];
	return pr_err("IPAddressRange %s-%s is a range, but should have been encoded as a prefix.",
	    addr2str6(&range->min, buf1),
	    addr2str6(&range->max, buf2));
}

static int
__check_encoding6(struct ipv6_range *range, unsigned int quadrant,
    uint32_t mask)
{
	uint32_t min;
	uint32_t max;

	for (; quadrant < 4; quadrant++) {
		min = addr6_get_quadrant(&range->min, quadrant);
		max = addr6_get_quadrant(&range->max, quadrant);
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
		min = addr6_get_quadrant(&range->min, quadrant);
		max = addr6_get_quadrant(&range->max, quadrant);
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
range6_decode(IPAddressRange_t const *input, struct ipv6_range *result)
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
