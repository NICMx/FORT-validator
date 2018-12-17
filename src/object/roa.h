#ifndef SRC_OBJECT_ROA_H_
#define SRC_OBJECT_ROA_H_

#include <openssl/x509.h>

int handle_roa(char const *, STACK_OF(X509_CRL) *);

#endif /* SRC_OBJECT_ROA_H_ */
