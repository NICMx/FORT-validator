#ifndef SRC_VRPS_H_
#define SRC_VRPS_H_

#include <netinet/ip.h>

struct vrp;
struct delta;

int deltas_db_init(void);

struct delta *create_delta(void);
struct vrp *create_vrp4(u_int32_t, struct in_addr, u_int8_t, u_int8_t);
struct vrp *create_vrp6(u_int32_t, struct in6_addr, u_int8_t, u_int8_t);

int delta_add_vrp(struct delta *, struct vrp *);
int deltas_db_add_delta(struct delta *);

void vrp_destroy(struct vrp **);
void delta_destroy(struct delta *);
void deltas_db_destroy();

#endif /* SRC_VRPS_H_ */
