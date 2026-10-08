#ifndef VALIDATOR_OBJECT_ROA_H_
#define VALIDATOR_OBJECT_ROA_H_

#include "validator/object/certificate.h"

int roa_traverse(struct validation_thread *, struct cache_mapping const *,
    struct rpki_certificate *);

#endif /* VALIDATOR_OBJECT_ROA_H_ */
