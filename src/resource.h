#ifndef SRC_RESOURCE_H_
#define SRC_RESOURCE_H_

#include <stdbool.h>
#include <libcmscodec/ASIdentifiers.h>
#include <libcmscodec/IPAddressFamily.h>
#include "address.h"

int get_addr_family(OCTET_STRING_t *);

struct resources;

struct resources *resources_create(void);
void resources_destroy(struct resources *);

int resources_add_ip(struct resources *, struct IPAddressFamily *);
int resources_add_asn(struct resources *, struct ASIdentifiers *);

bool resources_empty(struct resources *);
bool resources_contains_asn(struct resources *, long);
bool resources_contains_ipv4(struct resources *, struct ipv4_prefix *);
bool resources_contains_ipv6(struct resources *, struct ipv6_prefix *);

#endif /* SRC_RESOURCE_H_ */
