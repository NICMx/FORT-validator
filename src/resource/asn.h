#ifndef SRC_RESOURCE_ASN_H_
#define SRC_RESOURCE_ASN_H_

#include <stdbool.h>
#include "asn1/asn1c/ASId.h"

struct resources_asn;

struct resources_asn *rasn_create(void);
void rasn_get(struct resources_asn *);
void rasn_put(struct resources_asn *);

int rasn_add(struct resources_asn *, unsigned long, unsigned long);
bool rasn_empty(struct resources_asn *);
bool rasn_contains(struct resources_asn *, unsigned long, unsigned long);

#endif /* SRC_RESOURCE_ASN_H_ */
