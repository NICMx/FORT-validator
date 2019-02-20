#ifndef SRC_OBJECT_SIGNED_OBJECT_H_
#define SRC_OBJECT_SIGNED_OBJECT_H_

#include <openssl/x509.h>
#include "asn1/oid.h"
#include "asn1/signed_data.h"

typedef int (*signed_object_cb)(OCTET_STRING_t *, void *);

int signed_object_decode(struct signed_object_args *, struct oid_arcs const *,
    signed_object_cb, void *);

#endif /* SRC_OBJECT_SIGNED_OBJECT_H_ */
