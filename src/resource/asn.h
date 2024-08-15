#ifndef SRC_RESOURCE_ASN_H_
#define SRC_RESOURCE_ASN_H_

#include <stdbool.h>

#include "as_number.h"

/*
 * Implementation note: This is just a casted struct sorted_array.
 * Why? Because this module doesn't have anything to add.
 * Why not make the methods return a sorted_array? Because they're not meant to
 * be tied to the sorted array implementation.
 * Why not convert this into a structure that contains a sorted_array? Because
 * sorted_array is private, so resources_asn would have to contain a pointer to
 * it, which is another level of indirection, which is slightly wasted
 * performance.
 */
struct resources_asn;

struct resources_asn *rasn_create(void);
void rasn_get(struct resources_asn *);
void rasn_put(struct resources_asn *);

int rasn_add(struct resources_asn *, struct asn_range const *);
bool rasn_empty(struct resources_asn *);
bool rasn_contains(struct resources_asn *, struct asn_range const *);

typedef int (*foreach_asn_cb)(struct asn_range const *, void *);
int rasn_foreach(struct resources_asn *, foreach_asn_cb, void *);

#endif /* SRC_RESOURCE_ASN_H_ */
