#ifndef SRC_CERTIFICATE_REFS_H_
#define SRC_CERTIFICATE_REFS_H_

#include "rpp.h"

/**
 * Some of the URLs defined in Access Descriptions of a certificate's
 * extensions.
 *
 * It's intended to address some awkward RFC requirements:
 * RFC 6487 defines that these "MUST reference" certain files. I think the best
 * way to validate this is to check that they equal the respective URLs from the
 * manifest (because these will at some point be validated as part of the
 * traversal anyway). Problem is, these URLs are not guaranteed to be parsed by
 * the time the extension validation kicks in. So we store them in this
 * structure and handle them later.
 *
 * It makes a mess out of the code, and I'm not even sure that validating them
 * is our responsibility, but there you go.
 */
struct certificate_refs {
	/**
	 * CRL Distribution Points's fullName. Non-TA certificates only.
	 * RFC 6487, section 4.8.6.
	 */
	char *crldp;
	/**
	 * AIA's caIssuers. Non-TA certificates only.
	 * RFC 6487, section 4.8.7.
	 */
	struct rpki_uri *caIssuers;
	/**
	 * SIA's signedObject. EE certificates only.
	 * RFC 6487, section 4.8.8.2.
	 */
	struct rpki_uri *signedObject;
};

void refs_init(struct certificate_refs *);
void refs_cleanup(struct certificate_refs *);
int refs_validate_ca(struct certificate_refs *, struct rpp const *);
int refs_validate_ee(struct certificate_refs *, struct rpp const *,
    struct rpki_uri *);
int refs_validate_ee_checklist(struct certificate_refs *, struct rpp const *);

#endif /* SRC_CERTIFICATE_REFS_H_ */
