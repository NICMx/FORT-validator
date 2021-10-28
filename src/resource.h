#ifndef SRC_RESOURCE_H_
#define SRC_RESOURCE_H_

#include <stdbool.h>
#include "resource/asn.h"
#include "types/address.h"
#include "asn1/asn1c/ASIdentifiers.h"
#include "asn1/asn1c/IPAddressFamily.h"

enum rpki_policy {
	/**
	 * If certificate `x`'s resources are not a subset of `x - 1`'s
	 * resources, then `x` is to be rejected.
	 */
	RPKI_POLICY_RFC6484,
	/**
	 * If certificate `x`'s resources are not a subset of `x - 1`'s
	 * resources, then the overclaiming resources are to be ignored.
	 */
	RPKI_POLICY_RFC8360,
};

int get_addr_family(OCTET_STRING_t *);

struct resources;

struct resources *resources_create(bool);
void resources_destroy(struct resources *);

int resources_add_ip(struct resources *, struct IPAddressFamily *);
int resources_add_asn(struct resources *, struct ASIdentifiers *, bool);

bool resources_empty(struct resources *);
bool resources_contains_asn(struct resources *, unsigned long);
bool resources_contains_ipv4(struct resources *, struct ipv4_prefix *);
bool resources_contains_ipv6(struct resources *, struct ipv6_prefix *);

enum rpki_policy resources_get_policy(struct resources *);
void resources_set_policy(struct resources *, enum rpki_policy);

int resources_foreach_asn(struct resources *, foreach_asn_cb, void *);

#endif /* SRC_RESOURCE_H_ */
