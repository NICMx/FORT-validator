#ifndef SRC_OID_H_
#define SRC_OID_H_

#include <stdbool.h>
#include <libcmscodec/AlgorithmIdentifier.h>
#include "common.h"

/* These objects are expected to live on the stack. */
struct oid_arcs {
	asn_oid_arc_t *arcs;
	size_t count;
};

void free_arcs(struct oid_arcs *);

typedef asn_oid_arc_t OID[];

/* Please update MAX_ARCS if you add an OID that has more arcs. */
static const OID SIGNED_DATA_OID = { 1, 2, 840, 113549, 1, 7, 2 };
static const OID CONTENT_TYPE_ATTR_OID = { 1, 2, 840, 113549, 1, 9, 3 };
static const OID MESSAGE_DIGEST_ATTR_OID = { 1, 2, 840, 113549, 1, 9, 4 };
static const OID SIGNING_TIME_ATTR_OID = { 1, 2, 840, 113549, 1, 9, 5 };
static const OID BINARY_SIGNING_TIME_ATTR_OID = { 1, 2, 840, 113549, 1, 9, 16,
    2, 46 };
static const OID ROA_OID = { 1, 2, 840, 113549, 1, 9, 16, 1, 24 };
static const OID OID_SHA224 = { 2, 16, 840, 1, 101, 3, 4, 2, 4 };
static const OID OID_SHA256 = { 2, 16, 840, 1, 101, 3, 4, 2, 1 };
static const OID OID_SHA384 = { 2, 16, 840, 1, 101, 3, 4, 2, 2 };
static const OID OID_SHA512 = { 2, 16, 840, 1, 101, 3, 4, 2, 3 };

int oid2arcs(OBJECT_IDENTIFIER_t *, struct oid_arcs *);
int any2arcs(ANY_t *, struct oid_arcs *);

bool arcs_equal(struct oid_arcs *, struct oid_arcs *);
/* Use ARCS_EQUAL_OID() instead. */
bool arcs_equal_oids(struct oid_arcs *, asn_oid_arc_t const *, size_t);

/*
 * a is supposed to be a OBJECT_IDENTIFIER_t (from libcmscodec.)
 * b is supposed to be an OID.
 */
#define ARCS_EQUAL_OIDS(a, b) arcs_equal_oids(a, b, ARRAY_LEN(b))

void oid_print(OBJECT_IDENTIFIER_t *oid);

#endif /* SRC_OID_H_ */
