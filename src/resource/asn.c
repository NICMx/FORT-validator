#include "resource/asn.h"

#include <errno.h>
#include <limits.h>

#include "log.h"
#include "sorted_array.h"

struct asn_cb {
	foreach_asn_cb cb;
	void *arg;
};

static enum sarray_comparison
asn_cmp(void const *arg1, void const *arg2)
{
	uint32_t n1min = ((struct asn_range const *) arg1)->min;
	uint32_t n1max = ((struct asn_range const *) arg1)->max;
	uint32_t n2min = ((struct asn_range const *) arg2)->min;
	uint32_t n2max = ((struct asn_range const *) arg2)->max;

	if (n1min == n2min && n1max == n2max)
		return SACMP_EQUAL;
	if (n1min <= n2min && n2max <= n1max)
		return SACMP_CHILD;
	if (n2min <= n1min && n1max <= n2max)
		return SACMP_PARENT;
	if (n2min != 0 && n1max == n2min - 1)
		return SACMP_ADJACENT_RIGHT;
	if (n1max < n2min)
		return SACMP_RIGHT;
	if (n1min != 0 && n2max == n1min - 1)
		return SACMP_ADJACENT_LEFT;
	if (n2max < n1min)
		return SACMP_LEFT;

	return SACMP_INTERSECTION;
}

struct resources_asn *
rasn_create(void)
{
	return (struct resources_asn *)
	    sarray_create(sizeof(struct asn_range), asn_cmp);
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
rasn_add(struct resources_asn *asns, struct asn_range const *range)
{
	return sarray_add((struct sorted_array *) asns, range);
}

bool
rasn_empty(struct resources_asn *asns)
{
	return sarray_empty((struct sorted_array *) asns);
}

bool
rasn_contains(struct resources_asn *asns, struct asn_range const *range)
{
	return sarray_contains((struct sorted_array *) asns, range);
}

static int
asn_range_cb(void *node, void *arg)
{
	struct asn_cb *param = arg;
	return param->cb(node, param->arg);
}

int
rasn_foreach(struct resources_asn *asns, foreach_asn_cb cb, void *arg)
{
	struct asn_cb param = { .cb = cb, .arg = arg };
	return sarray_foreach((struct sorted_array *) asns, asn_range_cb,
	    &param);
}
