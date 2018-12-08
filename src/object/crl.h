#ifndef SRC_OBJECT_CRL_H_
#define SRC_OBJECT_CRL_H_

#include <openssl/x509.h>
#include "state.h"

int crl_load(struct validation *, char const *, X509_CRL **);

#endif /* SRC_OBJECT_CRL_H_ */
