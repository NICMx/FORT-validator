#ifndef SRC_OBJECT_ROA_H_
#define SRC_OBJECT_ROA_H_

#include "asn1/signed_data.h"
#include "types/map.h"

int roa_traverse(struct cache_mapping *, struct rpki_certificate *);

#endif /* SRC_OBJECT_ROA_H_ */
