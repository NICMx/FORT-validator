#ifndef SRC_RTR_DB_DB_TABLE_H_
#define SRC_RTR_DB_DB_TABLE_H_

#include "rtr/db/delta.h"
#include "types/address.h"

struct db_table;

struct db_table *db_table_create(void);
void db_table_destroy(struct db_table *);

int db_table_join(struct db_table *, struct db_table *);

unsigned int db_table_roa_count(struct db_table *);
unsigned int db_table_roa_count_v4(struct db_table *);
unsigned int db_table_roa_count_v6(struct db_table *);
unsigned int db_table_router_key_count(struct db_table *);

int db_table_foreach_roa(struct db_table const *, vrp_foreach_cb, void *);
void db_table_remove_roa(struct db_table *, struct vrp const *);

int db_table_foreach_router_key(struct db_table const *, router_key_foreach_cb,
    void *);
void db_table_remove_router_key(struct db_table *, struct router_key const *);

int rtrhandler_handle_roa_v4(struct db_table *, uint32_t,
    struct ipv4_prefix const *, uint8_t);
int rtrhandler_handle_roa_v6(struct db_table *, uint32_t,
    struct ipv6_prefix const *, uint8_t);
int rtrhandler_handle_router_key(struct db_table *, unsigned char const *,
    uint32_t, unsigned char const *);
struct deltas *compute_deltas(struct db_table *, struct db_table *);

#endif /* SRC_RTR_DB_DB_TABLE_H_ */
