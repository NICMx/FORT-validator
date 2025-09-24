#ifndef SRC_OBJECT_MANIFEST_H_
#define SRC_OBJECT_MANIFEST_H_

#include "asn1/signed_data.h"
#include "cache.h"

int manifest_traverse(struct cache_mapping const *, struct cache_cage *,
    struct rpki_certificate *);

#endif /* SRC_OBJECT_MANIFEST_H_ */
