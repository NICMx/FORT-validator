#ifndef VALIDATOR_ASN1_ASN1C_CRL_H_
#define VALIDATOR_ASN1_ASN1C_CRL_H_

#include <jansson.h>
#include <openssl/bio.h>

json_t *CRL_bio2json(BIO *bio);

#endif /* VALIDATOR_ASN1_ASN1C_CRL_H_ */
