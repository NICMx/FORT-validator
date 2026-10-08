#ifndef SRC_SIGNED_DATA_H_
#define SRC_SIGNED_DATA_H_

/* Some wrappers for asn1/asn1c/SignedData.h. */

#include "asn1/asn1c/SignedData.h"
#include "object/certificate.h"

struct signed_object;
struct rpki_certificate;

int signed_data_decode(ANY_t *, struct SignedData **);
int signed_data_validate(struct signed_object *, struct rpki_certificate *);

int get_content_type_attr(struct SignedData *, OBJECT_IDENTIFIER_t **);

#endif /* SRC_SIGNED_DATA_H_ */
