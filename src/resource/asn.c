#include "asn.h"

#include "sorted_array.h"

struct asn_node {
	ASId_t min;
	ASId_t max;
};

static enum sarray_comparison
asn_cmp(void *arg1, void *arg2)
{
	ASId_t n1min = ((struct asn_node *) arg1)->min;
	ASId_t n2min = ((struct asn_node *) arg2)->min;
	ASId_t n1max = ((struct asn_node *) arg1)->max;
	ASId_t n2max = ((struct asn_node *) arg2)->max;

	if (n1min == n2min && n1max == n2max)
		return SACMP_EQUAL;
	if (n1min <= n2min && n2max <= n1max)
		return SACMP_CHILD;
	if (n2min <= n1min && n1max <= n2max)
		return SACMP_PARENT;
	if (n1max == n2min - 1)
		return SACMP_ADJACENT_RIGHT;
	if (n1max < n2min)
		return SACMP_RIGHT;
	if (n2max == n1min - 1)
		return SACMP_ADJACENT_LEFT;
	if (n2max < n1min)
		return SACMP_LEFT;

	return SACMP_INTERSECTION;
}

struct resources_asn *
rasn_create(void)
{
	return (struct resources_asn *)
	    sarray_create(sizeof(struct asn_node), asn_cmp);
}

void
rasn_get(struct resources_asn *asns)
{
	sarray_get((struct sorted_array *) asns);
}

void
rasn_put(struct resources_asn *asns)
{
	sarray_put((struct sorted_array *) asns);
}

int
rasn_add(struct resources_asn *asns, ASId_t min, ASId_t max)
{
	struct asn_node n = { min, max };
	return sarray_add((struct sorted_array *) asns, &n);
}

bool
rasn_contains(struct resources_asn *asns, ASId_t min, ASId_t max)
{
	struct asn_node n = { min, max };
	return sarray_contains((struct sorted_array *) asns, &n);
}

int
rasn_join(struct resources_asn *r1, struct resources_asn *r2)
{
	return sarray_join((struct sorted_array *) r1,
	    (struct sorted_array *) r2);
}
