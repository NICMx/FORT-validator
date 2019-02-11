#include "asn.h"

#include <errno.h>

#include "log.h"
#include "sorted_array.h"

struct asn_node {
	unsigned long min;
	unsigned long max;
};

static enum sarray_comparison
asn_cmp(void *arg1, void *arg2)
{
	unsigned long n1min = ((struct asn_node *) arg1)->min;
	unsigned long n1max = ((struct asn_node *) arg1)->max;
	unsigned long n2min = ((struct asn_node *) arg2)->min;
	unsigned long n2max = ((struct asn_node *) arg2)->max;

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
rasn_add(struct resources_asn *asns, unsigned long min, unsigned long max)
{
	struct asn_node n = { min, max };
	return sarray_add((struct sorted_array *) asns, &n);
}

bool
rasn_empty(struct resources_asn *asns)
{
	return sarray_empty((struct sorted_array *) asns);
}

bool
rasn_contains(struct resources_asn *asns, unsigned long min, unsigned long max)
{
	struct asn_node n = { min, max };
	return sarray_contains((struct sorted_array *) asns, &n);
}
