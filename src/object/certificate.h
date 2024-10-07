#ifndef SRC_OBJECT_CERTIFICATE_H_
#define SRC_OBJECT_CERTIFICATE_H_

#include <openssl/x509.h>
#include <sys/queue.h>

#include "asn1/asn1c/ANY.h"
#include "asn1/asn1c/SignatureValue.h"
#include "cache.h"
#include "certificate_refs.h"
#include "resource.h"
#include "state.h"
#include "types/rpp.h"

/* Certificate types in the RPKI */
enum cert_type {
	CERTYPE_TA,		/* Trust Anchor */
	CERTYPE_CA,		/* Certificate Authority */
	CERTYPE_BGPSEC,		/* BGPsec certificates */
	CERTYPE_EE,		/* End Entity certificates */
	CERTYPE_UNKNOWN,
};

struct rpki_certificate {
	struct cache_mapping map;		/* Nonexistent on EEs */
	X509 *x509;				/* Initializes after dequeue */

	enum cert_type type;
	enum rpki_policy policy;		/* XXX seems redundant */
	struct resources *resources;
	struct sia_uris sias;

	struct rpki_certificate *parent;
	struct rpp rpp;				/* Nonexistent on EEs */

	SLIST_ENTRY(rpki_certificate) lh;	/* List Hook */
	unsigned int refcount;
};

void rpki_certificate_init_ee(struct rpki_certificate *,
    struct rpki_certificate *, bool);
void rpki_certificate_cleanup(struct rpki_certificate *);
void rpki_certificate_free(struct rpki_certificate *);

/**
 * Performs the basic (RFC 5280, presumably) chain validation.
 * (Ignores the IP and AS extensions.)
 */
int certificate_validate_chain(struct rpki_certificate *);
/**
 * Validates RFC 6487 compliance.
 * (Except extensions.)
 */
int certificate_validate_rfc6487(struct rpki_certificate *);

int certificate_validate_signature(X509 *, ANY_t *coded, SignatureValue_t *);

/**
 * Extracts the resources from cert->x509 into cert->resources.
 *
 * Note: One reason why this is separate from the validate_extensions functions
 * is because it needs to be handled after the policy has been extracted from
 * the certificate policies extension, and handle_extensions() currently does
 * not care about order. I don't know if you'll find other reasons if you choose
 * to migrate it.
 */
int certificate_get_resources(struct rpki_certificate *cert);

/**
 * Validates the certificate extensions, End-Entity style.
 *
 * Also initializes the second argument with the references found in the
 * extensions.
 */
int certificate_validate_extensions_ee(struct rpki_certificate *,
    OCTET_STRING_t *);
int certificate_validate_extensions_bgpsec(void);

/*
 * Specific validation of AIA (rfc6487#section-4.8.7) extension, public so that
 * CAs and EEs can access it.
 */
int certificate_validate_aia(struct rpki_certificate *);

int traverse_tree(struct cache_mapping const *, struct validation *);

#endif /* SRC_OBJECT_CERTIFICATE_H_ */
