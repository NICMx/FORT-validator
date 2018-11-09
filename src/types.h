#ifndef _SRC_COMMON_TYPES_H
#define _SRC_COMMON_TYPES_H

/**
 * @file
 * The NAT64's core data types. Structures used all over the code.
 *
 * Both the kernel module and the userspace application can see this file.
 */

#include <asm/types.h>
#include <linux/types.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "log.h"



/**
 * A layer-3 (IPv4) identifier attached to a layer-4 identifier.
 * Because they're paired all the time in this project.
 */
struct ipv4_transport_addr {
	/** The layer-3 identifier. */
	struct in_addr l3;
	/** The layer-4 identifier (Either the TCP/UDP port or the ICMP id). */
	__u16 l4;
};

/**
 * A layer-3 (IPv6) identifier attached to a layer-4 identifier.
 * Because they're paired all the time in this project.
 */
struct ipv6_transport_addr {
	/** The layer-3 identifier. */
	struct in6_addr l3;
	/** The layer-4 identifier (Either the TCP/UDP port or the ICMP id). */
	__u16 l4;
};

#endif /* _COMMON_TYPES_H */
