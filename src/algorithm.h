#ifndef SRC_ALGORITHM_H_
#define SRC_ALGORITHM_H_

#include <libcmscodec/AlgorithmIdentifier.h>
#include <libcmscodec/OBJECT_IDENTIFIER.h>

/**
 * This file is an implementation of RFC 7935 (previously 6485).
 */

int validate_certificate_signature_algorithm(int, char const *);
int validate_certificate_public_key_algorithm(int);

int validate_cms_hashing_algorithm(AlgorithmIdentifier_t *, char const *);
int validate_cms_hashing_algorithm_oid(OBJECT_IDENTIFIER_t *, char const *);
int validate_cms_signature_algorithm(AlgorithmIdentifier_t *);

#endif /* SRC_ALGORITHM_H_ */
