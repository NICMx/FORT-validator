#ifndef SRC_OBJECT_CRL_H_
#define SRC_OBJECT_CRL_H_

#include <openssl/x509.h>

int crl_load(char const *, X509_CRL **);

#endif /* SRC_OBJECT_CRL_H_ */
