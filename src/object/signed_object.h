#ifndef SRC_OBJECT_SIGNED_OBJECT_H_
#define SRC_OBJECT_SIGNED_OBJECT_H_

#include "asn1/oid.h"
#include "resource.h"
#include "state.h"

int signed_object_decode(struct validation *, char const *,
    asn_TYPE_descriptor_t const *, struct oid_arcs const *, void **,
    struct resources *);

#endif /* SRC_OBJECT_SIGNED_OBJECT_H_ */
