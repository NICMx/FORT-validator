#ifndef SRC_DELTA_H_
#define SRC_DELTA_H_

#include "types/delta.h"

struct deltas;

int deltas_create(struct deltas **);
void deltas_refget(struct deltas *);
void deltas_refput(struct deltas *);

int deltas_add_roa(struct deltas *, struct vrp const *, int,
    char, unsigned int, unsigned int);
int deltas_add_router_key(struct deltas *, struct router_key const *, int);

bool deltas_is_empty(struct deltas *);
int deltas_foreach(struct deltas *, delta_vrp_foreach_cb,
    delta_router_key_foreach_cb, void *);
void deltas_print(struct deltas *);

#endif /* SRC_DELTA_H_ */
