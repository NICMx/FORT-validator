#include "oid.h"

#include <errno.h>
#include "common.h"
#include "log.h"
#include "asn1/decode.h"

void
free_arcs(struct oid_arcs *arcs)
{
	free(arcs->arcs);
}

/*
 * Wrapper for OBJECT_IDENTIFIER_get_arcs().
 *
 * Callers must free @result.
 *
 * TODO (fine) Most of the time, this function is called to compare @result
 * to some oid. Maybe create a wrapper that takes care of all the boilerplate.
 */
int
oid2arcs(OBJECT_IDENTIFIER_t *oid, struct oid_arcs *result)
{
	static const size_t MAX_ARCS = 9;
	ssize_t count;
	ssize_t count2;
	asn_oid_arc_t *tmp;

	result->arcs = malloc(MAX_ARCS * sizeof(asn_oid_arc_t));
	if (result->arcs == NULL)
		enomem_panic();

	count = OBJECT_IDENTIFIER_get_arcs(oid, result->arcs, MAX_ARCS);
	if (count < 0) {
		pr_val_err("OBJECT_IDENTIFIER_get_arcs() returned %zd.", count);
		free(result->arcs);
		return count;
	}

	result->count = count;

	/* If necessary, reallocate arcs array and try again. */
	if (count > MAX_ARCS) {
		tmp = realloc(result->arcs, count * sizeof(asn_oid_arc_t));
		if (tmp == NULL)
			enomem_panic();
		result->arcs = tmp;

		count2 = OBJECT_IDENTIFIER_get_arcs(oid, result->arcs, count);
		if (count != count2) {
			pr_val_err("OBJECT_IDENTIFIER_get_arcs() returned %zd. (expected %zd)",
			    count2, count);
			free(result->arcs);
			return -EINVAL;
		}
	}

	return 0;
}

bool oid_equal(OBJECT_IDENTIFIER_t *a, OBJECT_IDENTIFIER_t *b)
{
	return (a->size == b->size) && (memcmp(a->buf, b->buf, a->size) == 0);
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
