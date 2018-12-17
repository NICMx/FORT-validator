#ifndef SRC_OBJECT_MANIFEST_H_
#define SRC_OBJECT_MANIFEST_H_

#include <openssl/x509.h>

int handle_manifest(char const *, STACK_OF(X509_CRL) *);

#endif /* SRC_OBJECT_MANIFEST_H_ */
