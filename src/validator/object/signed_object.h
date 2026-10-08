#ifndef VALIDATOR_OBJECT_SIGNED_OBJECT_H_
#define VALIDATOR_OBJECT_SIGNED_OBJECT_H_

#include "common/types/map.h"
#include "validator/asn1/asn1c/ContentInfo.h"
#include "validator/asn1/asn1c/SignedData.h"
#include "validator/asn1/oid.h"

enum so_type {
	SOT_ROA = 1,
	SOT_ASPA,
	SOT_MFT,
	SOT_GBR,
};

struct signed_object {
	enum so_type type;
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

#endif /* VALIDATOR_OBJECT_SIGNED_OBJECT_H_ */
