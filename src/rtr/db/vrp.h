#ifndef SRC_RTR_DB_VRP_H_
#define SRC_RTR_DB_VRP_H_

#include <stdint.h>
#include <netinet/in.h>

#define FLAG_WITHDRAWAL		0
#define FLAG_ANNOUNCEMENT	1

#define VRP_ASN_EQ(a, b)						\
	(a)->asn == (b)->asn

#define VRP_MAX_PREFIX_LEN_EQ(a, b)					\
	(a)->max_prefix_length == (b)->max_prefix_length

#define VRP_PREFIX_V4_EQ(a, b)						\
	((a)->addr_fam == AF_INET &&					\
	(b)->addr_fam == AF_INET &&					\
	(a)->prefix.v4.s_addr == (b)->prefix.v4.s_addr &&		\
	(a)->prefix_length == (b)->prefix_length)

#define VRP_PREFIX_V6_EQ(a, b)						\
	((a)->addr_fam == AF_INET6 &&					\
	(b)->addr_fam == AF_INET6 &&					\
	IN6_ARE_ADDR_EQUAL(&(a)->prefix.v6, &(b)->prefix.v6) &&		\
	(a)->prefix_length == (b)->prefix_length)

#define VRP_PREFIX_EQ(a, b)						\
	(VRP_PREFIX_V4_EQ(a, b) || VRP_PREFIX_V6_EQ(a, b))

#define VRP_EQ(a, b)							\
	(VRP_ASN_EQ(a, b) && VRP_PREFIX_EQ(a, b) && VRP_MAX_PREFIX_LEN_EQ(a, b))

typedef uint32_t serial_t;

struct vrp {
	uint32_t	asn;
	union {
		struct	in_addr v4;
		struct	in6_addr v6;
	} prefix;
	uint8_t	prefix_length;
	uint8_t	max_prefix_length;
	uint8_t	addr_fam;
};

struct delta {
	serial_t serial;
	struct vrp vrp;
	uint8_t flags;
};

typedef int (*vrp_foreach_cb)(struct vrp const *, void *);
typedef int (*delta_foreach_cb)(struct delta const *, void *);

#endif /* SRC_RTR_DB_VRP_H_ */
