#ifndef VALIDATOR_OBJECT_ASPA_H_
#define VALIDATOR_OBJECT_ASPA_H_

#include "validator/object/certificate.h"

int aspa_traverse(struct validation_thread *, struct cache_mapping const *,
    struct rpki_certificate *);

#endif /* VALIDATOR_OBJECT_ASPA_H_ */
