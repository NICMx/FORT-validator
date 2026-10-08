#ifndef VALIDATOR_OBJECT_MANIFEST_H_
#define VALIDATOR_OBJECT_MANIFEST_H_

#include "validator/object/certificate.h"

int manifest_traverse(struct cache_mapping const *, struct rpp_querier *,
    struct rpki_certificate *);

#endif /* VALIDATOR_OBJECT_MANIFEST_H_ */
