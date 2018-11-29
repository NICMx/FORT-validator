#ifndef SRC_OBJECT_CERTIFICATE_H_
#define SRC_OBJECT_CERTIFICATE_H_

#include <stdbool.h>
#include <openssl/x509.h>
#include "resource.h"
#include "state.h"

bool is_certificate(char const *);
int certificate_load(struct validation *, const char *, X509 **);

/*
 * Note: You actually need all three of these functions for a full validation;
 * certificate_validate() checks the certificate's relationship with its
 * parents, certificate_get_resources() covers the IP and ASN extensions, and
 * you will need certificate_traverse() to walk through the children.
 */

int certificate_validate(struct validation *, X509 *, STACK_OF(X509_CRL) *);
int certificate_get_resources(struct validation *, X509 *, struct resources *);
int certificate_traverse(struct validation *, X509 *);

#endif /* SRC_OBJECT_CERTIFICATE_H_ */
