#ifndef SRC_SIGNED_DATA_H_
#define SRC_SIGNED_DATA_H_

/* Some wrappers for asn1/asn1c/SignedData.h. */

#include "asn1/asn1c/SignedData.h"
#include "certificate_refs.h"
#include "resource.h"

struct ee_cert {
	/** CRL that might or might not revoke the EE certificate. */
	STACK_OF(X509_CRL) *crls;
	/** A copy of the resources carried by the EE certificate. */
	struct resources *res;
	/**
	 * A bunch of URLs found in the EE certificate's extensions,
	 * recorded for future validation.
	 */
	struct certificate_refs refs;
};

void eecert_init(struct ee_cert *, STACK_OF(X509_CRL) *, bool);
void eecert_cleanup(struct ee_cert *);

int signed_data_decode(ANY_t *, struct SignedData **);
int signed_data_validate(ANY_t *, struct SignedData *, struct ee_cert *);

int get_content_type_attr(struct SignedData *, OBJECT_IDENTIFIER_t **);

#endif /* SRC_SIGNED_DATA_H_ */
