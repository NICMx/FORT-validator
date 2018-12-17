#ifndef SRC_OBJECT_CERTIFICATE_H_
#define SRC_OBJECT_CERTIFICATE_H_

#include <stdbool.h>
#include <openssl/x509.h>
#include "resource.h"

bool is_certificate(char const *);
int certificate_load(const char *, X509 **);

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
 * Handles the SIA extension, CA style.
 * (ie. Recursively walks through the certificate's children.)
 */
int certificate_traverse_ca(X509 *, STACK_OF(X509_CRL) *);
/**
 * Handles the SIA extension, EE style.
 * (Doesn't actually "traverse" anything. The name is just for the sake of
 * mirroring.)
 */
int certificate_traverse_ee(X509 *);

#endif /* SRC_OBJECT_CERTIFICATE_H_ */
