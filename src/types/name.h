#ifndef SRC_TYPES_NAME_H_
#define SRC_TYPES_NAME_H_

#include <openssl/x509.h>
#include <stdbool.h>

struct rfc5280_name;

/* Constructor */
int x509_name_decode(X509_NAME *, char const *, struct rfc5280_name **);
/* Reference counting */
void x509_name_get(struct rfc5280_name *);
void x509_name_put(struct rfc5280_name *);

/* Getters */
char const *x509_name_commonName(struct rfc5280_name *);
char const *x509_name_serialNumber(struct rfc5280_name *);

bool x509_name_equals(struct rfc5280_name *, struct rfc5280_name *);


/* X509_NAME utils */
int validate_issuer_name(char const *, X509_NAME *);

void x509_name_pr_debug(char const *, X509_NAME *);

#endif /* SRC_TYPES_NAME_H_ */
