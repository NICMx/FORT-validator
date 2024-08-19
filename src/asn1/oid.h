#ifndef SRC_OID_H_
#define SRC_OID_H_

#include "asn1/asn1c/OBJECT_IDENTIFIER.h"
#include "common.h"

/* These objects are expected to live on the stack. */
struct oid_arcs {
	char const *name;
	asn_oid_arc_t *arcs;
	size_t count;
};

#define OID2ARCS(_name, oid) {						\
	.name = _name,							\
	.arcs = oid,							\
	.count = ARRAY_LEN(oid),					\
}

void free_arcs(struct oid_arcs *);

typedef asn_oid_arc_t OID[];

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! Please update oid2arcs().MAX_ARCS if you add an OID that has more arcs. !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */

#define OID_SIGNED_DATA              { 1, 2, 840, 113549, 1, 7, 2 }
#define OID_CONTENT_TYPE_ATTR        { 1, 2, 840, 113549, 1, 9, 3 }
#define OID_MESSAGE_DIGEST_ATTR      { 1, 2, 840, 113549, 1, 9, 4 }
#define OID_SIGNING_TIME_ATTR        { 1, 2, 840, 113549, 1, 9, 5 }
#define OID_BINARY_SIGNING_TIME_ATTR { 1, 2, 840, 113549, 1, 9, 16, 2, 46 }

#define OID_ROA                      { 1, 2, 840, 113549, 1, 9, 16, 1, 24 }
#define OID_MANIFEST                 { 1, 2, 840, 113549, 1, 9, 16, 1, 26 }
#define OID_GHOSTBUSTERS             { 1, 2, 840, 113549, 1, 9, 16, 1, 35 }

int oid2arcs(OBJECT_IDENTIFIER_t *, struct oid_arcs *);

bool oid_equal(OBJECT_IDENTIFIER_t *, OBJECT_IDENTIFIER_t *);
bool arcs_equal(struct oid_arcs const *, struct oid_arcs const *);
/* Use ARCS_EQUAL_OID() instead. */
bool arcs_equal_oids(struct oid_arcs *, asn_oid_arc_t const *, size_t);

/*
 * a is supposed to be a OBJECT_IDENTIFIER_t.
 * b is supposed to be an OID.
 */
#define ARCS_EQUAL_OIDS(a, b) arcs_equal_oids(a, b, ARRAY_LEN(b))

#endif /* SRC_OID_H_ */
