#ifndef SRC_RESOURCE_ASN_H_
#define SRC_RESOURCE_ASN_H_

#include <stdbool.h>
#include <libcmscodec/ASId.h>

struct resources_asn;

struct resources_asn *rasn_create(void);
void rasn_get(struct resources_asn *);
void rasn_put(struct resources_asn *);

int rasn_add(struct resources_asn *, ASId_t, ASId_t);
bool rasn_contains(struct resources_asn *, ASId_t, ASId_t);
int rasn_join(struct resources_asn *, struct resources_asn *);

#endif /* SRC_RESOURCE_ASN_H_ */
