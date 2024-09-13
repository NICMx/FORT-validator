#ifndef SRC_CERT_STACK_H_
#define SRC_CERT_STACK_H_

#include <openssl/bn.h>

#include "object/certificate.h"
#include "types/name.h"

struct cert_stack;

struct deferred_cert {
	struct cache_mapping map;
	struct rpp *pp;
};

int certstack_create(struct cert_stack **);
void certstack_destroy(struct cert_stack *);

void deferstack_push(struct cert_stack *, struct cache_mapping *, struct rpp *);
int deferstack_pop(struct cert_stack *, struct deferred_cert *cert);

int x509stack_push(struct cert_stack *, struct cache_mapping *, X509 *,
    enum rpki_policy, enum cert_type);
void x509stack_cancel(struct cert_stack *);
X509 *x509stack_peek(struct cert_stack *);
struct resources *x509stack_peek_resources(struct cert_stack *);
void x509stack_store_serial(struct cert_stack *, BIGNUM *);

STACK_OF(X509) *certstack_get_x509s(struct cert_stack *);
int certstack_get_x509_num(struct cert_stack *);

#endif /* SRC_CERT_STACK_H_ */
