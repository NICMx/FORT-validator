#ifndef SRC_OBJECT_CERTIFICATE_H_
#define SRC_OBJECT_CERTIFICATE_H_

#include <openssl/x509.h>
#include <stdatomic.h>
#include <sys/queue.h>

#include "asn1/asn1c/ANY.h"
#include "asn1/asn1c/SignatureValue.h"
#include "cache.h"
#include "resource.h"
#include "types/rpp.h"

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

	SLIST_ENTRY(rpki_certificate) lh;	/* List Hook */
	atomic_uint refcount;
};

void cer_init_ee(struct rpki_certificate *, struct rpki_certificate *, bool);
void cer_cleanup(struct rpki_certificate *);
void cer_free(struct rpki_certificate *);

validation_verdict cer_traverse(struct rpki_certificate *);

struct signed_object;
int cer_validate_ee(struct rpki_certificate *, struct signed_object *);

#endif /* SRC_OBJECT_CERTIFICATE_H_ */
