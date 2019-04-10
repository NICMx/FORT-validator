#ifndef SRC_VRPS_H_
#define SRC_VRPS_H_

#include <time.h>
#include <netinet/ip.h>

#define NO_DATA_AVAILABLE	-2
#define DIFF_UNDETERMINED	-1
#define NO_DIFF			0
#define DIFF_AVAILABLE		1

struct vrp {
	u_int32_t	asn;
	union {
		struct	in_addr ipv4_prefix;
		struct	in6_addr ipv6_prefix;
	};
	u_int8_t	prefix_length;
	u_int8_t	max_prefix_length;
	u_int8_t	addr_fam;
	u_int8_t	flags;
};

struct router_key {
	u_int8_t	flags;
	unsigned char	*ski;
	size_t		ski_len;
	u_int32_t	asn;
	unsigned char	*spki;
	size_t		spki_len;
};

int deltas_db_init(void);

struct vrp create_vrp4(u_int32_t, struct in_addr, u_int8_t, u_int8_t);
struct vrp create_vrp6(u_int32_t, struct in6_addr, u_int8_t, u_int8_t);

int deltas_db_create_delta(struct vrp *, unsigned int);
int deltas_db_status(u_int32_t *);

unsigned int get_vrps_delta(u_int32_t *, u_int32_t *, struct vrp **);
unsigned int get_router_keys_delta(u_int32_t *, u_int32_t *,
    struct router_key **);

void deltas_db_destroy(void);
void set_vrps_last_modified_date(time_t);

u_int32_t get_last_serial_number(void);
u_int16_t get_current_session_id(u_int8_t);
time_t get_vrps_last_modified_date(void);

#endif /* SRC_VRPS_H_ */
