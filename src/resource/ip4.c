#include "ip4.h"

#include "sorted_array.h"

struct r4_node {
	uint32_t min; /* This is an IPv4 address in host byte order */
	uint32_t max; /* This is an IPv4 address in host byte order */
};

static enum sarray_comparison
r4_cmp(void const *arg1, void const *arg2)
{
	uint32_t n1min = ((struct r4_node const *) arg1)->min;
	uint32_t n2min = ((struct r4_node const *) arg2)->min;
	uint32_t n1max = ((struct r4_node const *) arg1)->max;
	uint32_t n2max = ((struct r4_node const *) arg2)->max;

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

static void
pton(struct ipv4_prefix const *p, struct r4_node *n)
{
	n->min = ntohl(p->addr.s_addr);
	n->max = n->min | u32_suffix_mask(p->len);
}

static void
rton(struct ipv4_range const *r, struct r4_node *n)
{
	n->min = ntohl(r->min.s_addr);
	n->max = ntohl(r->max.s_addr);
}

struct resources_ipv4 *
res4_create(void)
{
	return (struct resources_ipv4 *)
	    sarray_create(sizeof(struct r4_node), r4_cmp);
}

void
res4_get(struct resources_ipv4 *ips)
{
	sarray_get((struct sorted_array *) ips);
}

void
res4_put(struct resources_ipv4 *ips)
{
	sarray_put((struct sorted_array *) ips);
}

int
res4_add_prefix(struct resources_ipv4 *ips, struct ipv4_prefix const *prefix)
{
	struct r4_node n;
	pton(prefix, &n);
	return sarray_add((struct sorted_array *) ips, &n);
}

int
res4_add_range(struct resources_ipv4 *ips, struct ipv4_range const *range)
{
	struct r4_node n;
	rton(range, &n);
	return sarray_add((struct sorted_array *) ips, &n);
}

bool
res4_empty(struct resources_ipv4 const *ips)
{
	return sarray_empty((struct sorted_array const *) ips);
}

bool
res4_contains_prefix(struct resources_ipv4 *ips,
    struct ipv4_prefix const *prefix)
{
	struct r4_node n;

	if (ips == NULL)
		return false;

	pton(prefix, &n);
	return sarray_contains((struct sorted_array *) ips, &n);
}

bool
res4_contains_range(struct resources_ipv4 *ips, struct ipv4_range const *range)
{
	struct r4_node n;
	rton(range, &n);
	return sarray_contains((struct sorted_array *) ips, &n);
}
