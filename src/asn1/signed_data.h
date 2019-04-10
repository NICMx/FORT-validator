#ifndef SRC_SIGNED_DATA_H_
#define SRC_SIGNED_DATA_H_

/* Some wrappers for libcmscodec's SignedData. */

#include <openssl/x509.h>
#include <libcmscodec/SignedData.h>
#include "resource.h"
#include "object/certificate.h"

/*
 * This only exists to reduce argument lists.
 */
struct signed_object_args {
	/** Location of the signed object. */
	struct rpki_uri const *uri;
	/** CRL that might or might not revoke the embedded certificate. */
	STACK_OF(X509_CRL) *crls;
	/** A copy of the resources carried by the embedded certificate. */
	struct resources *res;
	/**
	 * A bunch of URLs found in the embedded certificate's extensions,
	 * recorded for future validation.
	 */
	struct certificate_refs refs;
	/** Certificate's subject name field */
	struct rfc5280_name *subject_name;
};

int signed_object_args_init(struct signed_object_args *,
    struct rpki_uri const *, STACK_OF(X509_CRL) *, bool);
void signed_object_args_cleanup(struct signed_object_args *);

int signed_data_decode(ANY_t *, struct signed_object_args *args,
    struct SignedData **);
void signed_data_free(struct SignedData *);

int get_content_type_attr(struct SignedData *, OBJECT_IDENTIFIER_t **);

#endif /* SRC_SIGNED_DATA_H_ */
