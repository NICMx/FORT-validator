#ifndef SRC_VRPS_H_
#define SRC_VRPS_H_

#include <netinet/ip.h>

struct vrp {
	u_int32_t	asn;
	union {
		struct	in_addr ipv4_prefix;
		struct	in6_addr ipv6_prefix;
	};
	u_int8_t	prefix_length;
	u_int8_t	max_prefix_length;
	u_int8_t	in_addr_len;
	u_int8_t	flags;
};

struct delta;

int deltas_db_init(void);

struct delta *create_delta(void);
struct vrp *create_vrp4(u_int32_t, struct in_addr, u_int8_t, u_int8_t);
struct vrp *create_vrp6(u_int32_t, struct in6_addr, u_int8_t, u_int8_t);
struct vrp **get_vrps_delta(u_int32_t, unsigned int *);

int delta_add_vrp(struct delta *, struct vrp *);
int deltas_db_add_delta(struct delta *);

void vrp_destroy(struct vrp **);
void delta_destroy(struct delta *);
void deltas_db_destroy(void);

u_int32_t last_serial_number(void);

#endif /* SRC_VRPS_H_ */
