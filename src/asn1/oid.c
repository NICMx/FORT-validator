#include "oid.h"

#include <errno.h>
#include "common.h"
#include "asn1/decode.h"

#define MAX_ARCS 9

void
free_arcs(struct oid_arcs *arcs)
{
	free(arcs->arcs);
}

/*
 * Wrapper for OBJECT_IDENTIFIER_get_arcs().
 *
 * Callers must free @result.
 */
int
oid2arcs(OBJECT_IDENTIFIER_t *oid, struct oid_arcs *result)
{
	ssize_t count, count2;

	result->arcs = malloc(MAX_ARCS * sizeof(asn_oid_arc_t));
	if (result->arcs == NULL)
		return -ENOMEM;

	count = OBJECT_IDENTIFIER_get_arcs(oid, result->arcs, MAX_ARCS);
	if (count < 0) {
		free(result->arcs);
		return count;
	}

	result->count = count;

	/* If necessary, reallocate arcs array and try again. */
	if (count > MAX_ARCS) {
		result->arcs = realloc(result->arcs, count * sizeof(asn_oid_arc_t));
		if (!result->arcs)
			return -ENOMEM;
		count2 = OBJECT_IDENTIFIER_get_arcs(oid, result->arcs, count);
		if (count != count2) {
			free(result->arcs);
			return -EINVAL;
		}
	}

	return 0;
}

/* Callers must free @result. */
int
any2arcs(struct validation *state, ANY_t *any, struct oid_arcs *result)
{
	OBJECT_IDENTIFIER_t *oid;
	int error;

	error = asn1_decode_any(state, any, &asn_DEF_OBJECT_IDENTIFIER,
	    (void **) &oid);
	if (error)
		return error;

	error = oid2arcs(oid, result);
	ASN_STRUCT_FREE(asn_DEF_OBJECT_IDENTIFIER, oid);
	return error;
}

static bool __arcs_equal(asn_oid_arc_t const *a, size_t a_count,
    asn_oid_arc_t const *b, size_t b_count)
{
	long int i;

	if (a_count != b_count)
		return false;

	/* Most OIDs start with the same numbers, so iterate backwards. */
	for (i = a_count - 1; i >= 0; i--) {
		if (a[i] != b[i])
			return false;
	}

	return true;
}

bool arcs_equal(struct oid_arcs const *a, struct oid_arcs const *b)
{
	return __arcs_equal(a->arcs, a->count, b->arcs, b->count);
}

bool arcs_equal_oids(struct oid_arcs *arcs, asn_oid_arc_t const *oids,
    size_t oids_len)
{
	return __arcs_equal(arcs->arcs, arcs->count, oids, oids_len);
}
