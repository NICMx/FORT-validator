#ifndef SRC_OBJECT_MANIFEST_H_
#define SRC_OBJECT_MANIFEST_H_

#include <openssl/sha.h>
#include <openssl/x509.h>

#include "cache.h"
#include "object/certificate.h"

int manifest_traverse(struct cache_mapping const *, struct cache_cage *,
    struct rpki_certificate *);

#endif /* SRC_OBJECT_MANIFEST_H_ */
