#ifndef SRC_OBJECT_CERTIFICATE_H_
#define SRC_OBJECT_CERTIFICATE_H_

#include <stdbool.h>
#include <openssl/x509.h>
#include "resource.h"
#include "uri.h"

int certificate_load(struct rpki_uri const *, X509 **);

/**
 * Performs the basic (RFC 5280, presumably) chain validation.
 * (Ignores the IP, AS and SIA extensions.)
 */
int certificate_validate_chain(X509 *, STACK_OF(X509_CRL) *);
/**
 * Validates RFC 6487 compliance.
 * (Except IP, AS and SIA extensions.)
 */
int certificate_validate_rfc6487(X509 *, bool);

/**
 * Returns the IP and AS resources declared in the respective extensions.
 */
int certificate_get_resources(X509 *, struct resources *);

/**
 * Handles the SIA extension, Trust Anchor style.
 * (ie. Recursively walks through the certificate's children.)
 */
int certificate_traverse_ta(X509 *, STACK_OF(X509_CRL) *);
/**
 * Handles the SIA extension, (intermediate) CA style.
 * (ie. Recursively walks through the certificate's children.)
 */
int certificate_traverse_ca(X509 *, STACK_OF(X509_CRL) *);
/**
 * Handles the SIA extension, EE style.
 * (Doesn't actually "traverse" anything. The name is just for the sake of
 * mirroring.)
 */
int certificate_traverse_ee(X509 *, OCTET_STRING_t *);

#endif /* SRC_OBJECT_CERTIFICATE_H_ */
