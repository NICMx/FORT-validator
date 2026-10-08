#ifndef VALIDATOR_OBJECT_CERTIFICATE_H_
#define VALIDATOR_OBJECT_CERTIFICATE_H_

#include <sys/queue.h>

#include "validator/cache.h"
#include "validator/object/tal.h"
#include "validator/resource.h"
#include "validator/types/vthread.h"

/*
 * rfc6487#section-7.2, last paragraph.
 * Prevents arbitrarily long paths and loops.
 * XXX X509_VERIFY_MAX_CHAIN_CERTS
 * XXX optimize
 */
#define CER_MAX_DEPTH 32

/* Certificate types in the RPKI */
enum cert_type {
	CERTYPE_TA,		/* Trust Anchor */
	CERTYPE_CA,		/* Certificate Authority */
	CERTYPE_BGPSEC,		/* BGPsec certificates */
	CERTYPE_EE,		/* End Entity certificates */
	CERTYPE_UNKNOWN,
};

struct rpki_certificate {
	struct cache_mapping map;		/* Nonexistent on EEs */
	X509 *x509;				/* Initializes after dequeue */

	enum cert_type type;
	enum rpki_policy policy;
	struct resources *resources;
	struct extension_uris uris;

	struct tal *tal;			/* Only needed by TAs for now */
	struct rpki_certificate *parent;
	struct rpp rpp;				/* Nonexistent on EEs */

	struct rpp_querier *querier;

	SLIST_ENTRY(rpki_certificate) lh;	/* List Hook */
	atomic_uint refcount;
};

void cer_init_ee(struct rpki_certificate *, struct rpki_certificate *, bool);
void cer_cleanup(struct rpki_certificate *);
void cer_free(struct rpki_certificate *);

validation_verdict cer_traverse(struct validation_thread *,
    struct rpki_certificate *);

struct signed_object;
int cer_validate_ee(struct rpki_certificate *, struct signed_object *);

#endif /* VALIDATOR_OBJECT_CERTIFICATE_H_ */
