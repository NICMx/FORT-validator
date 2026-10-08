#ifndef VALIDATOR_OBJECT_GHOSTBUSTERS_H_
#define VALIDATOR_OBJECT_GHOSTBUSTERS_H_

#include "validator/object/certificate.h"

int ghostbusters_traverse(struct cache_mapping const *,
    struct rpki_certificate *);

#endif /* VALIDATOR_OBJECT_GHOSTBUSTERS_H_ */
