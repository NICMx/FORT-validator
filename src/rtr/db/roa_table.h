#ifndef SRC_ROA_TABLE_H_
#define SRC_ROA_TABLE_H_

#include "rtr/db/delta.h"
#include "rtr/db/vrp.h"

struct roa_table;

/* Constructor */
struct roa_table *roa_table_create(void);
/* Reference counting */
void roa_table_get(struct roa_table *);
void roa_table_put(struct roa_table *);

int roa_table_foreach_roa(struct roa_table *, vrp_foreach_cb, void *);

int rtrhandler_reset(struct roa_table *);
int rtrhandler_handle_roa_v4(struct roa_table *, uint32_t,
    struct ipv4_prefix const *, uint8_t);
int rtrhandler_handle_roa_v6(struct roa_table *, uint32_t,
    struct ipv6_prefix const *, uint8_t);

int compute_deltas(struct roa_table *, struct roa_table *, struct deltas **);

#endif /* SRC_ROA_TABLE_H_ */
