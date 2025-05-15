#ifndef SRC_OBJECT_SIGNED_OBJECT_H_
#define SRC_OBJECT_SIGNED_OBJECT_H_

#include "asn1/asn1c/ContentInfo.h"
#include "asn1/asn1c/SignedData.h"
#include "asn1/oid.h"
#include "types/map.h"

struct signed_object {
	struct cache_mapping const *map;
	struct ContentInfo *cinfo;
	struct SignedData *sdata;
	OCTET_STRING_t const *sid;
	SignatureValue_t const *signature;
};

int signed_object_decode(struct signed_object *, struct cache_mapping const *);

struct rpki_certificate;
int signed_object_validate(struct signed_object *, struct rpki_certificate *,
    struct oid_arcs const *);

void signed_object_cleanup(struct signed_object *);

#endif /* SRC_OBJECT_SIGNED_OBJECT_H_ */
