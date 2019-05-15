#ifndef SRC_RTR_DB_VRP_H_
#define SRC_RTR_DB_VRP_H_

#include <stdint.h>
#include <netinet/in.h>

#define FLAG_WITHDRAWAL		0
#define FLAG_ANNOUNCEMENT	1

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
