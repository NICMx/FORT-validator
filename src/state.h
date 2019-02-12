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

enum pubkey_state {
	PKS_VALID,
	PKS_INVALID,
	PKS_UNTESTED,
};

void validation_pubkey_valid(struct validation *);
void validation_pubkey_invalid(struct validation *);
enum pubkey_state validation_pubkey_state(struct validation *);

int validation_push_cert(struct validation *, struct rpki_uri const *, X509 *,
    enum rpki_policy, bool);
int validation_pop_cert(struct validation *);
X509 *validation_peek_cert(struct validation *);
struct rpki_uri const *validation_peek_cert_uri(struct validation *);

struct resources *validation_peek_resource(struct validation *);

int validation_store_serial_number(struct validation *, BIGNUM *);
int validation_store_subject(struct validation *, char *);

char *validation_get_ip_buffer1(struct validation *);
char *validation_get_ip_buffer2(struct validation *);

#endif /* SRC_STATE_H_ */
