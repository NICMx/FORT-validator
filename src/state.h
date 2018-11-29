#ifndef SRC_STATE_H_
#define SRC_STATE_H_

#include <openssl/bio.h>
#include <openssl/x509.h>
#include "resource.h"

struct validation;

int validation_create(struct validation **, char *);
void validation_destroy(struct validation *);

BIO *validation_stdout(struct validation *);
BIO *validation_stderr(struct validation *);
X509_STORE *validation_store(struct validation *);
STACK_OF(X509) *validation_certs(struct validation *);
struct restack *validation_resources(struct validation *);

int validation_push_cert(struct validation *, X509 *, struct resources *);
int validation_pop_cert(struct validation *);
X509 *validation_peek_cert(struct validation *);

struct resources *validation_peek_resource(struct validation *);

#endif /* SRC_STATE_H_ */
