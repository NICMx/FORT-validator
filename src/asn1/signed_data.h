#ifndef SRC_SIGNED_DATA_H_
#define SRC_SIGNED_DATA_H_

/* Some wrappers for asn1/asn1c/SignedData.h. */

#include <openssl/x509.h>
#include "resource.h"
#include "asn1/asn1c/SignedData.h"
#include "object/certificate.h"

/*
 * This only exists to reduce argument lists.
 */
struct signed_object_args {
	/** Location of the signed object. */
	struct rpki_uri *uri;
	/** CRL that might or might not revoke the embedded certificate. */
	STACK_OF(X509_CRL) *crls;
	/** A copy of the resources carried by the embedded certificate. */
	struct resources *res;
	/** Check if the certificate is revoked at CRLDP, not at crls stack */
	bool use_crldp;
	/**
	 * A bunch of URLs found in the embedded certificate's extensions,
	 * recorded for future validation.
	 */
	struct certificate_refs refs;
};

int signed_object_args_init(struct signed_object_args *, struct rpki_uri *,
    STACK_OF(X509_CRL) *, bool, bool);
void signed_object_args_cleanup(struct signed_object_args *);

int signed_data_decode(ANY_t *, struct signed_object_args *args,
    struct SignedData **);
void signed_data_free(struct SignedData *);

int get_content_type_attr(struct SignedData *, OBJECT_IDENTIFIER_t **);

#endif /* SRC_SIGNED_DATA_H_ */
