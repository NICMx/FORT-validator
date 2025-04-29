#ifndef SRC_CERTIFICATE_REFS_H_
#define SRC_CERTIFICATE_REFS_H_

/* XXX delete this */

#include "cache.h"

int validate_cdp(struct sia_uris const *, struct uri const *);
int refs_validate_ee(struct sia_uris const *, struct uri const *,
    struct uri const *);

#endif /* SRC_CERTIFICATE_REFS_H_ */
