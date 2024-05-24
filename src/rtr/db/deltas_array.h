#ifndef SRC_RTR_DB_DELTAS_ARRAY_H_
#define SRC_RTR_DB_DELTAS_ARRAY_H_

#include "rtr/db/delta.h"
#include "types/serial.h"

struct deltas_array;

struct deltas_array *darray_create(void);
void darray_destroy(struct deltas_array *);

unsigned int darray_len(struct deltas_array *);
void darray_add(struct deltas_array *, struct deltas *);
void darray_clear(struct deltas_array *);

typedef int (*darray_foreach_cb)(struct deltas *, void *);
int darray_foreach_since(struct deltas_array *, serial_t from,
    darray_foreach_cb, void *);

#endif /* SRC_RTR_DB_DELTAS_ARRAY_H_ */
