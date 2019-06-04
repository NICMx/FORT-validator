#ifndef SRC_OBJECT_MANIFEST_H_
#define SRC_OBJECT_MANIFEST_H_

#include <openssl/x509.h>
#include "uri.h"
#include "rpp.h"

int handle_manifest(struct rpki_uri *, STACK_OF(X509_CRL) *, struct rpp **);

#endif /* SRC_OBJECT_MANIFEST_H_ */
