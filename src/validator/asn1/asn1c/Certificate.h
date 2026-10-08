#ifndef VALIDATOR_ASN1_ASN1C_CERTIFICATE_H_
#define VALIDATOR_ASN1_ASN1C_CERTIFICATE_H_

#include <openssl/bio.h>

#include "validator/asn1/asn1c/ANY.h"

json_t *Certificate_any2json(ANY_t *);
json_t *Certificate_bio2json(BIO *);

#endif /* VALIDATOR_ASN1_ASN1C_CERTIFICATE_H_ */
