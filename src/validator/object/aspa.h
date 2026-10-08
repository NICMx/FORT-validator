#ifndef SRC_OBJECT_ASPA_H_
#define SRC_OBJECT_ASPA_H_

#include "object/certificate.h"
#include "types/map.h"
#include "types/vthread.h"

int aspa_traverse(struct validation_thread *, struct cache_mapping const *,
    struct rpki_certificate *);

#endif /* SRC_OBJECT_ASPA_H_ */
