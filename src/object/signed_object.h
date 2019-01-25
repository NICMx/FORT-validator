#ifndef SRC_OBJECT_SIGNED_OBJECT_H_
#define SRC_OBJECT_SIGNED_OBJECT_H_

#include <openssl/x509.h>
#include "asn1/oid.h"
#include "asn1/signed_data.h"

int signed_object_decode(struct signed_object_args *args,
    asn_TYPE_descriptor_t const *, struct oid_arcs const *, void **);

#endif /* SRC_OBJECT_SIGNED_OBJECT_H_ */
