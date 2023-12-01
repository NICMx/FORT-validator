#ifndef SRC_RESOURCE_IP4_H_
#define SRC_RESOURCE_IP4_H_

#include "types/address.h"

struct resources_ipv4;

struct resources_ipv4 *res4_create(void);
void res4_get(struct resources_ipv4 *);
void res4_put(struct resources_ipv4 *);

int res4_add_prefix(struct resources_ipv4 *, struct ipv4_prefix const *);
int res4_add_range(struct resources_ipv4 *, struct ipv4_range const *);
bool res4_empty(struct resources_ipv4 const *);
bool res4_contains_prefix(struct resources_ipv4 *, struct ipv4_prefix const *);
bool res4_contains_range(struct resources_ipv4 *, struct ipv4_range const *);

#endif /* SRC_RESOURCE_IP4_H_ */
