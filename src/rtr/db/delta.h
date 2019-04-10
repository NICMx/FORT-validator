#ifndef SRC_DELTA_H_
#define SRC_DELTA_H_

#include "rtr/db/roa.h"
#include "rtr/db/vrp.h"

enum delta_op {
	DELTA_ADD,
	DELTA_RM,
};

struct deltas;

int deltas_create(struct deltas **);
void deltas_destroy(struct deltas *);

int deltas_add_roa_v4(struct deltas *, uint32_t, struct v4_address *,
    enum delta_op);
int deltas_add_roa_v6(struct deltas *, uint32_t, struct v6_address *,
    enum delta_op);

bool deltas_is_empty(struct deltas *);
int deltas_foreach(struct deltas *, vrp_foreach_cb , void *);

#endif /* SRC_DELTA_H_ */
