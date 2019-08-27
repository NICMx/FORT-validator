#ifndef SRC_OBJECT_SIGNED_OBJECT_H_
#define SRC_OBJECT_SIGNED_OBJECT_H_

#include "asn1/oid.h"
#include "asn1/signed_data.h"

struct signed_object {
	struct ContentInfo *cinfo;
	struct signed_data sdata;
};

int signed_object_decode(struct signed_object *, struct rpki_uri *);
int signed_object_validate(struct signed_object *, struct oid_arcs const *,
    struct signed_object_args *);
void signed_object_cleanup(struct signed_object *);

#endif /* SRC_OBJECT_SIGNED_OBJECT_H_ */
