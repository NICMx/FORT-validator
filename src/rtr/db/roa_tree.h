#ifndef SRC_ROA_TREE_H_
#define SRC_ROA_TREE_H_

#include "address.h"
#include "object/name.h"
#include "rtr/db/delta.h"
#include "rtr/db/vrp.h"

struct roa_tree;

/* Constructor */
struct roa_tree *roa_tree_create(void);
/* Reference counting */
void roa_tree_get(struct roa_tree *);
void roa_tree_put(struct roa_tree *);

int roa_tree_foreach_roa(struct roa_tree *, vrp_foreach_cb, void *);

/* TODO (urgent) rename to tree handler or whatever */
int forthandler_reset(struct roa_tree *);
int forthandler_go_down(struct roa_tree *, struct rfc5280_name *);
int forthandler_go_up(struct roa_tree *);
int forthandler_handle_roa_v4(struct roa_tree *, uint32_t,
    struct ipv4_prefix const *, uint8_t);
int forthandler_handle_roa_v6(struct roa_tree *, uint32_t,
    struct ipv6_prefix const *, uint8_t);

int compute_deltas(struct roa_tree *, struct roa_tree *, struct deltas **);

#endif /* SRC_ROA_TREE_H_ */
