#ifndef SRC_OBJECT_GHOSTBUSTERS_H_
#define SRC_OBJECT_GHOSTBUSTERS_H_

#include <openssl/x509.h>
#include "uri.h"
#include "rpp.h"

int ghostbusters_traverse(struct rpki_uri const *, struct rpp *,
    STACK_OF(X509_CRL) *);

#endif /* SRC_OBJECT_GHOSTBUSTERS_H_ */
