#ifndef SRC_CERT_STACK_H_
#define SRC_CERT_STACK_H_

#include <openssl/x509.h>
#include <stdbool.h>
#include "resource.h"
#include "object/certificate.h"
#include "object/name.h"
#include "types/uri.h"

/*
 * One certificate stack is allocated per validation cycle thread, and it is
 * used through its entirety to hold the certificates relevant to the ongoing
 * validation.
 *
 * Keep in mind: This module deals with two different (but correlated) stack
 * data structures, and they both store "certificates" (albeit in different
 * representations):
 *
 * - Defer stack: This one stores certificates whose validation has been
 *   postponed during the validation cycle. (They were found in some manifest
 *   list, and haven't been opened yet.)
 *   It prevents us from having to validate the RPKI tree in a recursive manner,
 *   which would be prone to stack overflow.
 * - x509 stack: Trusted stack. It is a chain of certificates, meant to be used
 *   as ancestors of the certificate being presently validated.
 */

struct cert_stack;

struct deferred_cert {
	struct rpki_uri *uri;
	struct rpp *pp;
};

int certstack_create(struct cert_stack **);
void certstack_destroy(struct cert_stack *);

int deferstack_push(struct cert_stack *, struct deferred_cert *cert);
int deferstack_pop(struct cert_stack *, struct deferred_cert *cert);

int x509stack_push(struct rpki_uri *, X509 *, enum rpki_policy, enum cert_type);
void x509stack_cancel(void);
X509 *x509stack_peek(void);
struct rpki_uri *x509stack_peek_uri(struct cert_stack *);
struct resources *x509stack_peek_resources(struct cert_stack *);
int x509stack_store_serial(struct cert_stack *, BIGNUM *);
typedef int (*subject_pk_check_cb)(bool *, char const *, void *);
int x509stack_store_subject(struct cert_stack *, struct rfc5280_name *,
    subject_pk_check_cb, void *);

STACK_OF(X509) *certstack_get_x509s(struct cert_stack *);
int certstack_get_x509_num(struct cert_stack *);

#endif /* SRC_CERT_STACK_H_ */
