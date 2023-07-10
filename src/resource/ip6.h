#ifndef SRC_RESOURCE_IP6_H_
#define SRC_RESOURCE_IP6_H_

#include <stdbool.h>
#include "types/address.h"

struct resources_ipv6;

struct resources_ipv6 *res6_create(void);
void res6_get(struct resources_ipv6 *);
void res6_put(struct resources_ipv6 *);

int res6_add_prefix(struct resources_ipv6 *ps, struct ipv6_prefix const *);
int res6_add_range(struct resources_ipv6 *, struct ipv6_range const *);
bool res6_empty(struct resources_ipv6 const *ips);
bool res6_contains_prefix(struct resources_ipv6 *, struct ipv6_prefix const *);
bool res6_contains_range(struct resources_ipv6 *, struct ipv6_range const *);

#endif /* SRC_RESOURCE_IP6_H_ */
