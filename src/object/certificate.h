#ifndef SRC_OBJECT_CERTIFICATE_H_
#define SRC_OBJECT_CERTIFICATE_H_

#include <stdbool.h>
#include <openssl/x509.h>
#include "certificate_refs.h"
#include "resource.h"
#include "rpp.h"
#include "uri.h"
#include "asn1/asn1c/ANY.h"
#include "asn1/asn1c/SignatureValue.h"

/* Certificate types in the RPKI */
enum cert_type {
	TA,		/* Trust Anchor */
	CA,		/* Certificate Authority */
	BGPSEC,		/* BGPsec certificates */
	EE,		/* End Entity certificates */
};

int certificate_load(struct rpki_uri *, X509 **);

/**
 * Performs the basic (RFC 5280, presumably) chain validation.
 * (Ignores the IP and AS extensions.)
 */
int certificate_validate_chain(X509 *, STACK_OF(X509_CRL) *);
/**
 * Validates RFC 6487 compliance.
 * (Except extensions.)
 */
int certificate_validate_rfc6487(X509 *, enum cert_type);

int certificate_validate_signature(X509 *, ANY_t *coded, SignatureValue_t *);

/**
 * Returns the IP and AS resources declared in the respective extensions.
 *
 * Note: One reason why this is separate from the validate_extensions functions
 * is because it needs to be handled after the policy has been extracted from
 * the certificate policies extension, and handle_extensions() currently does
 * not care about order. I don't know if you'll find other reasons if you choose
 * to migrate it.
 */
int certificate_get_resources(X509 *, struct resources *, enum cert_type);

/**
 * Validates the certificate extensions, End-Entity style.
 *
 * Also initializes the second argument with the references found in the
 * extensions.
 */
int certificate_validate_extensions_ee(X509 *, OCTET_STRING_t *,
    struct certificate_refs *, enum rpki_policy *);

int certificate_traverse(struct rpp *, struct rpki_uri *);

#endif /* SRC_OBJECT_CERTIFICATE_H_ */
