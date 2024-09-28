#ifndef SRC_STATE_H_
#define SRC_STATE_H_

#include <openssl/x509.h>

#include "object/tal.h"
#include "validation_handler.h"

struct validation;

int validation_prepare(struct validation **, struct tal *,
    struct validation_handler *);
void validation_destroy(struct validation *);

struct tal *validation_tal(struct validation *);
X509_STORE *validation_store(struct validation *);

void validation_pubkey_valid(struct validation *);
void validation_pubkey_invalid(struct validation *);

char *validation_get_ip_buffer1(struct validation *);
char *validation_get_ip_buffer2(struct validation *);

struct validation_handler const *
validation_get_validation_handler(struct validation *);

#endif /* SRC_STATE_H_ */
