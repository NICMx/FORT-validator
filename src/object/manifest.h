#ifndef SRC_OBJECT_MANIFEST_H_
#define SRC_OBJECT_MANIFEST_H_

#include <openssl/x509.h>
#include "uri.h"

int handle_manifest(struct rpki_uri const *, STACK_OF(X509_CRL) *);

#endif /* SRC_OBJECT_MANIFEST_H_ */
