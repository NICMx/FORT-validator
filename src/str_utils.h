#ifndef _SRC_STR_UTILS_H
#define _SRC_STR_UTILS_H

/**
 * @file
 * Two-liners (since you need to check the return value) for string-to-something
 * else conversions.
 * This is very noisy on the console on purpose because it is only used by the
 * parser of the userspace app's arguments.
 */

#include "types.h"

/** Maximum storable value on a __u8. */
#define MAX_U8 0xFFU
/** Maximum storable value on a __u16. */
#define MAX_U16 0xFFFFU
/** Maximum storable value on a __u32. */
#define MAX_U32 0xFFFFFFFFU
/** Maximum storable value on a __u64. */
#define MAX_U64 0xFFFFFFFFFFFFFFFFU


/**
 * Converts "str" to a IPv4 address. Stores the result in "result".
 *
 * Useful mainly in code common to kernelspace and userspace, since their conversion functions
 * differ, but meant to be used everywhere to strip the parameters from in4_pton() we don't want.
 */
int str_to_addr4(const char *, struct in_addr *);
/**
 * Converts "str" to a IPv6 address. Stores the result in "result".
 *
 * Useful mainly in code common to kernelspace and userspace, since their conversion functions
 * differ, but meant to be used everywhere to strip the parameters from in6_pton() we don't want.
 */
int str_to_addr6(const char *, struct in6_addr *);

/**
 * Parses @str as a boolean value, which it then copies to @out.
 */
int str_to_bool(const char *, __u8 *);

int validate_int(const char *);

/**
 * Parses @str" as a number, which it then copies to @out.
 * Refuses to succeed if @out is less than @min or higher than @max.
 */
int str_to_u8(const char *, __u8 *, __u8, __u8);
int str_to_u16(const char *, __u16 *, __u16, __u16);
int str_to_u32(const char *, __u32 *, __u32, __u32);
int str_to_u64(const char *, __u64 *, __u64, __u64);

/**
 * Parses @str as a comma-separated array of __u16s, which it then copies to
 * @out.
 * It sets @out_len as @out's length in elements (not bytes).
 */
int str_to_u16_array(const char *, __u16 **, size_t *);

/**
 * Parses @str as a '#' separated l3-address and l4-identifier, which it then
 * copies to @out".
 */
int str_to_addr4_port(const char *, struct ipv4_transport_addr *);
int str_to_addr6_port(const char *, struct ipv6_transport_addr *);

bool endsWith(char *, char *);

#endif /* _JOOL_COMM_STR_UTILS_H */
