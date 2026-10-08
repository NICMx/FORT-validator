#ifndef SRC_OBJECT_GHOSTBUSTERS_H_
#define SRC_OBJECT_GHOSTBUSTERS_H_

#include "asn1/signed_data.h"
#include "types/map.h"

int ghostbusters_traverse(struct cache_mapping const *,
    struct rpki_certificate *);

#endif /* SRC_OBJECT_GHOSTBUSTERS_H_ */
