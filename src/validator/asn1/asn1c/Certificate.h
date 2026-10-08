#ifndef SRC_ASN1_ASN1C_CERTIFICATE_H_
#define SRC_ASN1_ASN1C_CERTIFICATE_H_

#include <openssl/bio.h>

#include "asn1/asn1c/ANY.h"

json_t *Certificate_any2json(ANY_t *);
json_t *Certificate_bio2json(BIO *);

#endif /* SRC_ASN1_ASN1C_CERTIFICATE_H_ */
