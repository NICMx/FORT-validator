#ifndef SRC_SIGNED_DATA_H_
#define SRC_SIGNED_DATA_H_

/* Some wrappers for asn1/asn1c/SignedData.h. */

#include "resource.h"
#include "asn1/asn1c/SignedData.h"
#include "object/certificate.h"

/*
 * This only exists to reduce argument lists.
 * TODO (fine) rename to signed_data_args, since it has nothing to do with
 * signed objects anymore.
 */
struct signed_object_args {
	/** Location of the signed object. */
	struct rpki_uri *uri;
	/** CRL that might or might not revoke the embedded certificate. */
	STACK_OF(X509_CRL) *crls;
	/** A copy of the resources carried by the embedded certificate. */
	struct resources *res;
	/**
	 * A bunch of URLs found in the embedded certificate's extensions,
	 * recorded for future validation.
	 */
	struct certificate_refs refs;
};

void signed_object_args_init(struct signed_object_args *, struct rpki_uri *,
    STACK_OF(X509_CRL) *, bool);
void signed_object_args_cleanup(struct signed_object_args *);

struct signed_data {
	ANY_t *encoded;
	struct SignedData *decoded;
};

int signed_data_decode(struct signed_data *, ANY_t *);
int signed_data_validate(struct signed_data *, struct signed_object_args *);
void signed_data_cleanup(struct signed_data *);

int get_content_type_attr(struct SignedData *, OBJECT_IDENTIFIER_t **);

#endif /* SRC_SIGNED_DATA_H_ */
