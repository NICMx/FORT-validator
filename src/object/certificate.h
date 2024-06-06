#ifndef SRC_OBJECT_CERTIFICATE_H_
#define SRC_OBJECT_CERTIFICATE_H_

#include "asn1/asn1c/ANY.h"
#include "asn1/asn1c/SignatureValue.h"
#include "certificate_refs.h"
#include "resource.h"
#include "rpp.h"
#include "types/map.h"

/* Certificate types in the RPKI */
enum cert_type {
	CERTYPE_TA,		/* Trust Anchor */
	CERTYPE_CA,		/* Certificate Authority */
	CERTYPE_BGPSEC,		/* BGPsec certificates */
	CERTYPE_EE,		/* End Entity certificates */
};

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
int certificate_validate_extensions_bgpsec(X509 *, unsigned char **,
    enum rpki_policy *, struct rpp *);

/*
 * Specific validation of AIA (rfc6487#section-4.8.7) extension, public so that
 * CAs and EEs can access it.
 */
int certificate_validate_aia(struct cache_mapping *, X509 *);

int certificate_traverse(struct rpp *, struct cache_mapping *);

#endif /* SRC_OBJECT_CERTIFICATE_H_ */
