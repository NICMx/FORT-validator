#ifndef SRC_OBJECT_CRL_H_
#define SRC_OBJECT_CRL_H_

#include <openssl/x509.h>
#include "types/map.h"

int crl_load(struct cache_mapping *, X509 *, X509_CRL **);

#endif /* SRC_OBJECT_CRL_H_ */
