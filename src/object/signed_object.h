#ifndef SRC_OBJECT_SIGNED_OBJECT_H_
#define SRC_OBJECT_SIGNED_OBJECT_H_

#include <openssl/x509.h>
#include "asn1/oid.h"
#include "resource.h"
#include "uri.h"

int signed_object_decode(struct rpki_uri const *, asn_TYPE_descriptor_t const *,
    struct oid_arcs const *, void **, STACK_OF(X509_CRL) *, struct resources *);

#endif /* SRC_OBJECT_SIGNED_OBJECT_H_ */
