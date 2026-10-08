#ifndef VALIDATOR_RESOURCE_IP4_H_
#define VALIDATOR_RESOURCE_IP4_H_

#include "common/types/address.h"
#include "common/types/sorted_array.h"

struct resources_ipv4;

struct resources_ipv4 *res4_create(void);
void res4_get(struct resources_ipv4 *);
void res4_put(struct resources_ipv4 *);

enum resource_cmp_result res4_add_prefix(struct resources_ipv4 *,
    struct ipv4_prefix const *);
enum resource_cmp_result res4_add_range(struct resources_ipv4 *,
    struct ipv4_range const *);
bool res4_empty(struct resources_ipv4 const *);
bool res4_contains_prefix(struct resources_ipv4 *, struct ipv4_prefix const *);
bool res4_contains_range(struct resources_ipv4 *, struct ipv4_range const *);

#endif /* VALIDATOR_RESOURCE_IP4_H_ */
