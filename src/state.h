#ifndef SRC_STATE_H_
#define SRC_STATE_H_

#include <openssl/x509.h>
#include "resource.h"
#include "object/tal.h"

struct validation;

int validation_prepare(struct validation **, struct tal *);
void validation_destroy(struct validation *);

struct tal *validation_tal(struct validation *);
X509_STORE *validation_store(struct validation *);
STACK_OF(X509) *validation_certs(struct validation *);
struct restack *validation_resources(struct validation *);

int validation_push_cert(struct validation *, X509 *);
int validation_pop_cert(struct validation *);

struct resources *validation_peek_resource(struct validation *);

#endif /* SRC_STATE_H_ */
