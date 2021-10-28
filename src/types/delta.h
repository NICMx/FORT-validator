#ifndef SRC_TYPES_DELTA_H_
#define SRC_TYPES_DELTA_H_

#include "types/router_key.h"
#include "types/vrp.h"

#define FLAG_WITHDRAWAL		0
#define FLAG_ANNOUNCEMENT	1

struct delta_vrp {
	struct vrp vrp;
	uint8_t flags;
};

struct delta_router_key {
	struct router_key router_key;
	uint8_t flags;
};

typedef int (*delta_vrp_foreach_cb)(struct delta_vrp const *, void *);
typedef int (*delta_router_key_foreach_cb)(struct delta_router_key const *,
    void *);

int delta_vrp_print(struct delta_vrp const *, void *);
int delta_rk_print(struct delta_router_key const *, void *);

#endif /* SRC_TYPES_DELTA_H_ */
