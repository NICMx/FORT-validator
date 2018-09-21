#ifndef SRC_OID_H_
#define SRC_OID_H_

#include <stdbool.h>
#include "libcmscodec/AlgorithmIdentifier.h"

#include "common.h"

typedef asn_oid_arc_t OID[];

/* Please update MAX_ARCS if you add an OID that has more arcs. */
static const OID CONTENT_TYPE_ATTR_OID = {
    1, 2, 840, 113549, 1, 9, 3
};
static const OID MESSAGE_DIGEST_ATTR_OID = {
    1, 2, 840, 113549, 1, 9, 4
};
static const OID SIGNING_TIME_ATTR_OID = {
    1, 2, 840, 113549, 1, 9, 5
};
static const OID BINARY_SIGNING_TIME_ATTR_OID = {
    1, 2, 840, 113549, 1, 9, 16, 2, 46
};

/* Use OID_EQUALS() instead. */
bool oid_equals(OBJECT_IDENTIFIER_t *const actual_oid,
    asn_oid_arc_t const *expected_arcs, size_t len);

/*
 * a is supposed to be a OBJECT_IDENTIFIER_t (from libcmscodec.)
 * b is supposed to be an OID (from the typedef above.)
 */
#define OID_EQUALS(a, b) oid_equals(a, b, ARRAY_SIZE(b))

void oid_print(OBJECT_IDENTIFIER_t *oid);

bool is_digest_algorithm(AlgorithmIdentifier_t *algorithm);

#endif /* SRC_OID_H_ */
