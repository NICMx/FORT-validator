#ifndef SRC_SIGNED_DATA_H_
#define SRC_SIGNED_DATA_H_

/* Some wrappers for libcmscodec's SignedData. */

#include <openssl/x509.h>
#include <libcmscodec/SignedData.h>
#include "resource.h"
#include "object/certificate.h"

/*
 * This only exists to reduce argument lists.
 * TODO document fields.
 */
struct signed_object_args {
	STACK_OF(X509_CRL) *crls;
	struct resources *res;
	struct rpki_uri const *uri;
	struct certificate_refs refs;
};

int signed_data_decode(ANY_t *, struct signed_object_args *args,
    struct SignedData **);
void signed_data_free(struct SignedData *);

int get_content_type_attr(struct SignedData *, OBJECT_IDENTIFIER_t **);

#endif /* SRC_SIGNED_DATA_H_ */
