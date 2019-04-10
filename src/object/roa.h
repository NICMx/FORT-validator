#ifndef SRC_OBJECT_ROA_H_
#define SRC_OBJECT_ROA_H_

#include <openssl/x509.h>

#include "address.h"
#include "rpp.h"
#include "uri.h"

int roa_traverse(struct rpki_uri const *, struct rpp *, STACK_OF(X509_CRL) *);

#endif /* SRC_OBJECT_ROA_H_ */
