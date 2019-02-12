#ifndef SRC_OBJECT_CERTIFICATE_H_
#define SRC_OBJECT_CERTIFICATE_H_

#include <stdbool.h>
#include <openssl/x509.h>
#include "certificate_refs.h"
#include "resource.h"
#include "rpp.h"
#include "uri.h"

int certificate_load(struct rpki_uri const *, X509 **);

/**
 * Performs the basic (RFC 5280, presumably) chain validation.
 * (Ignores the IP and AS extensions.)
 */
int certificate_validate_chain(X509 *, STACK_OF(X509_CRL) *);
/**
 * Validates RFC 6487 compliance.
 * (Except extensions.)
 */
int certificate_validate_rfc6487(X509 *, bool);

/**
 * Returns the IP and AS resources declared in the respective extensions.
 *
 * TODO why is this not part of the certificate_validate*s, again?
 */
int certificate_get_resources(X509 *, struct resources *);

/**
 * Validates the certificate extensions, Trust Anchor style.
 *
 * Also initializes the second argument as the URI of the rpkiManifest Access
 * Description from the SIA extension.
 */
int certificate_validate_extensions_ta(X509 *, struct rpki_uri *,
    enum rpki_policy *);
/**
 * Validates the certificate extensions, (intermediate) Certificate Authority
 * style.
 *
 * Also initializes the second argument as the URI of the rpkiManifest Access
 * Description from the SIA extension.
 * Also initializes the third argument with the references found in the
 * extensions.
 */
int certificate_validate_extensions_ca(X509 *, struct rpki_uri *,
    struct certificate_refs *, enum rpki_policy *);
/**
 * Validates the certificate extensions, End-Entity style.
 *
 * Also initializes the second argument with the references found in the
 * extensions.
 */
int certificate_validate_extensions_ee(X509 *, OCTET_STRING_t *,
    struct certificate_refs *, enum rpki_policy *);

int certificate_traverse(struct rpp *, struct rpki_uri const *,
    STACK_OF(X509_CRL) *, bool);

#endif /* SRC_OBJECT_CERTIFICATE_H_ */
