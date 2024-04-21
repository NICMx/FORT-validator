#ifndef SRC_ASN1_ASN1C_CERTIFICATE_H_
#define SRC_ASN1_ASN1C_CERTIFICATE_H_

#include <jansson.h>
#include "asn1/asn1c/ANY.h"

json_t *Certificate_encode_json(ANY_t *ber);

#endif /* SRC_ASN1_ASN1C_CERTIFICATE_H_ */
