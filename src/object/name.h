#ifndef SRC_OBJECT_NAME_H_
#define SRC_OBJECT_NAME_H_

#include <stdbool.h>
#include <openssl/x509.h>

/**
 * It's an RFC5280 name, but from RFC 6487's perspective.
 * Meaning, only commonName and serialNumbers are allowed, and the latter is
 * optional.
 */
struct rfc5280_name {
	char *commonName;
	char *serialNumber;
};

int x509_name_decode(X509_NAME *, char const *, struct rfc5280_name *);
void x509_name_cleanup(struct rfc5280_name *);

bool x509_name_equals(struct rfc5280_name *, struct rfc5280_name *);

int validate_issuer_name(char const *, X509_NAME *);

#endif /* SRC_OBJECT_NAME_H_ */
