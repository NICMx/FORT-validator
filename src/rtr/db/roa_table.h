#ifndef SRC_ROA_TABLE_H_
#define SRC_ROA_TABLE_H_

#include "rtr/db/delta.h"
#include "rtr/db/vrp.h"

struct roa_table;

struct roa_table *roa_table_create(void);
void roa_table_destroy(struct roa_table *);
int roa_table_clone(struct roa_table **, struct roa_table *);

int roa_table_foreach_roa(struct roa_table *, vrp_foreach_cb, void *);
void roa_table_remove_roa(struct roa_table *, struct vrp const *);

int rtrhandler_reset(struct roa_table *);
int rtrhandler_handle_roa_v4(struct roa_table *, uint32_t,
    struct ipv4_prefix const *, uint8_t);
int rtrhandler_handle_roa_v6(struct roa_table *, uint32_t,
    struct ipv6_prefix const *, uint8_t);
int rtrhandler_merge(struct roa_table *, struct roa_table *);

int compute_deltas(struct roa_table *, struct roa_table *, struct deltas **);

#endif /* SRC_ROA_TABLE_H_ */
