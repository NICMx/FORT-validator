#ifndef SRC_VRPS_H_
#define SRC_VRPS_H_

#include <time.h>
#include <netinet/ip.h>

#define NO_DATA_AVAILABLE	-2
#define DIFF_UNDETERMINED	-1
#define NO_DIFF			0
#define DIFF_AVAILABLE		1

struct vrp {
	uint32_t	asn;
	union {
		struct	in_addr ipv4;
		struct	in6_addr ipv6;
	} prefix;
	uint8_t	prefix_length;
	uint8_t	max_prefix_length;
	uint8_t	addr_fam;
	uint8_t	flags;
};

int deltas_db_init(void);

struct vrp create_vrp4(uint32_t, struct in_addr, uint8_t, uint8_t);
struct vrp create_vrp6(uint32_t, struct in6_addr, uint8_t, uint8_t);

int deltas_db_create_delta(struct vrp *, unsigned int);
int deltas_db_status(uint32_t *);

unsigned int get_vrps_delta(uint32_t *, uint32_t *, struct vrp **);

void deltas_db_destroy(void);
void set_vrps_last_modified_date(time_t);

uint32_t get_last_serial_number(void);
uint16_t get_current_session_id(uint8_t);
time_t get_vrps_last_modified_date(void);

#endif /* SRC_VRPS_H_ */
