#ifndef SRC_OBJECT_ROA_H_
#define SRC_OBJECT_ROA_H_

#include "asn1/signed_data.h"
#include "types/map.h"
#include "types/vthread.h"

int roa_traverse(struct validation_thread *, struct cache_mapping const *,
    struct rpki_certificate *);

#endif /* SRC_OBJECT_ROA_H_ */
