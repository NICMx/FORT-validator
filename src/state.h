#ifndef SRC_STATE_H_
#define SRC_STATE_H_

#include <openssl/bio.h>

struct validation;

int validation_create(struct validation **, char *);
void validation_destroy(struct validation *);

int validation_push(struct validation *, X509 *);
void validation_pop(struct validation *);
X509 *validation_peek(struct validation *);

BIO *validation_stdout(struct validation *);
BIO *validation_stderr(struct validation *);

#endif /* SRC_STATE_H_ */
