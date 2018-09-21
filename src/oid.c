#include "oid.h"

#include <errno.h>
#include "common.h"

#define MAX_ARCS 9

/* Please update MAX_ARCS if you add an OID that has more arcs. */
static asn_oid_arc_t OID_SHA224[] = { 2, 16, 840, 1, 101, 3, 4, 2, 4 };
static asn_oid_arc_t OID_SHA256[] = { 2, 16, 840, 1, 101, 3, 4, 2, 1 };
static asn_oid_arc_t OID_SHA384[] = { 2, 16, 840, 1, 101, 3, 4, 2, 2 };
static asn_oid_arc_t OID_SHA512[] = { 2, 16, 840, 1, 101, 3, 4, 2, 3 };

/*
 * @a_oid is the original OID that's being tested.
 * @a_arcs must be a stack-allocated array of size @len.
 * @b_arcs is the expected array of arcs that needs to be compared to @a_oid.
 * Its length must be @len.
 */
bool
oid_equals(OBJECT_IDENTIFIER_t *const actual_oid,
    asn_oid_arc_t const *expected_arcs,
    size_t len)
{
	asn_oid_arc_t actual_arcs[MAX_ARCS];
	ssize_t count;
	long int i;

	count = OBJECT_IDENTIFIER_get_arcs(actual_oid, actual_arcs, len);
	if (count != len)
		return false;

	/* Most OIDs start with the same numbers, so iterate backwards. */
	for (i = len - 1; i >= 0; i--) {
		if (actual_arcs[i] != expected_arcs[i])
			return false;
	}

	return true;
}

void
oid_print(OBJECT_IDENTIFIER_t *oid)
{
	asn_fprint(stdout, &asn_DEF_OBJECT_IDENTIFIER, oid);
}

bool
is_digest_algorithm(AlgorithmIdentifier_t *algorithm)
{
	return OID_EQUALS(&algorithm->algorithm, OID_SHA224)
	    || OID_EQUALS(&algorithm->algorithm, OID_SHA256)
	    || OID_EQUALS(&algorithm->algorithm, OID_SHA384)
	    || OID_EQUALS(&algorithm->algorithm, OID_SHA512);
}
