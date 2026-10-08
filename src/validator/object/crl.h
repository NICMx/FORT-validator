#ifndef VALIDATOR_OBJECT_CRL_H_
#define VALIDATOR_OBJECT_CRL_H_

#include <openssl/x509.h>

#include "common/types/map.h"

int crl_load(struct cache_mapping const *, X509 *, X509_CRL **);

#endif /* VALIDATOR_OBJECT_CRL_H_ */
