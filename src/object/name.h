#ifndef SRC_OBJECT_NAME_H_
#define SRC_OBJECT_NAME_H_

#include <openssl/x509.h>

int x509_name_decode(X509_NAME *, int, char **);
int validate_issuer_name(char const *, X509_NAME *);

#endif /* SRC_OBJECT_NAME_H_ */
