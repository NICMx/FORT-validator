#ifndef SRC_DELTA_H_
#define SRC_DELTA_H_

#include "rtr/db/roa.h"
#include "rtr/db/vrp.h"

struct deltas;

int deltas_create(struct deltas **);
void deltas_get(struct deltas *);
void deltas_put(struct deltas *);

int deltas_add_roa_v4(struct deltas *, uint32_t, struct v4_address *, int);
int deltas_add_roa_v6(struct deltas *, uint32_t, struct v6_address *, int);

bool deltas_is_empty(struct deltas *);
int deltas_foreach(serial_t, struct deltas *, delta_foreach_cb , void *);

#endif /* SRC_DELTA_H_ */
