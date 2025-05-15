#ifndef SRC_ALGORITHM_H_
#define SRC_ALGORITHM_H_

#include <openssl/x509.h>

#include "asn1/asn1c/AlgorithmIdentifier.h"

/**
 * This file is an implementation of RFC 7935 (previously 6485) plus RFC 8608
 */

int validate_certificate_signature_algorithm(int, char const *);
int validate_certificate_public_key_algorithm(X509_ALGOR *);
int validate_certificate_public_key_algorithm_bgpsec(X509_ALGOR *);

int validate_cms_hash_algorithm(AlgorithmIdentifier_t *, char const *);
int validate_cms_hash_algorithm_oid(OBJECT_IDENTIFIER_t *, char const *);
int validate_cms_signature_algorithm(AlgorithmIdentifier_t *);

#endif /* SRC_ALGORITHM_H_ */
