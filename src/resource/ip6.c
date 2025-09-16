#include "resource/ip6.h"

#include <string.h>

#include "sorted_array.h"

static int
addr_cmp(struct in6_addr const *a, struct in6_addr const *b)
{
	/* The addresses are stored in big endian. */
	return memcmp(a, b, sizeof(uint32_t[4]));
}

/* a == b? */
static bool
addr_equals(struct in6_addr const *a, struct in6_addr const *b)
{
	return addr_cmp(a, b) == 0;
}

/* a <= b? */
static bool
addr_le(struct in6_addr const *a, struct in6_addr const *b)
{
	return addr_cmp(a, b) <= 0;
}

/* a < b? */
static bool
addr_lt(struct in6_addr const *a, struct in6_addr const *b)
{
	return addr_cmp(a, b) < 0;
}

/* a + 1 == b? */
static bool
addr_is_successor(struct in6_addr const *a, struct in6_addr const *b)
{
	struct in6_addr a_plus_1;
	int i;

	memcpy(&a_plus_1, a, sizeof(a_plus_1));
	for (i = 15; i >= 0; i--) {
		if (a_plus_1.s6_addr[i] != UINT8_MAX) {
			a_plus_1.s6_addr[i]++;
			return memcmp(&a_plus_1, b, sizeof(a_plus_1)) == 0;
		}
		a_plus_1.s6_addr[i] = 0;
	}

	return false; /* b cannot be the successor of 0xFFFFF...FFF */
}

static enum sarray_comparison
r6_cmp(void const *arg1, void const *arg2)
{
	struct in6_addr const *a1min = &((struct ipv6_range const *) arg1)->min;
	struct in6_addr const *a2min = &((struct ipv6_range const *) arg2)->min;
	struct in6_addr const *a1max = &((struct ipv6_range const *) arg1)->max;
	struct in6_addr const *a2max = &((struct ipv6_range const *) arg2)->max;

	if (addr_equals(a1min, a2min) && addr_equals(a1max, a2max))
		return SACMP_EQUAL;
	if (addr_le(a1min, a2min) && addr_le(a2max, a1max))
		return SACMP_CHILD;
	if (addr_le(a2min, a1min) && addr_le(a1max, a2max))
		return SACMP_PARENT;
	if (addr_is_successor(a1max, a2min))
		return SACMP_ADJACENT_RIGHT;
	if (addr_lt(a1max, a2min))
		return SACMP_RIGHT;
	if (addr_is_successor(a2max, a1min))
		return SACMP_ADJACENT_LEFT;
	if (addr_lt(a2max, a1min))
		return SACMP_LEFT;

	return SACMP_INTERSECTION;
}

static void
ptor(struct ipv6_prefix const *p, struct ipv6_range *r)
{
	r->min = p->addr;
	r->max = p->addr;
	ipv6_suffix_mask(p->len, &r->max);
}

struct resources_ipv6 *
res6_create(void)
{
	return (struct resources_ipv6 *)
	    sarray_create(sizeof(struct ipv6_range), r6_cmp);
}

void
res6_get(struct resources_ipv6 *ips)
{
	sarray_get((struct sorted_array *) ips);
}

void
res6_put(struct resources_ipv6 *ips)
{
	sarray_put((struct sorted_array *) ips);
}

int
res6_add_prefix(struct resources_ipv6 *ips, struct ipv6_prefix const *prefix)
{
	struct ipv6_range r;
	ptor(prefix, &r);
	return sarray_add((struct sorted_array *) ips, &r);
}

int
res6_add_range(struct resources_ipv6 *ips, struct ipv6_range const *range)
{
	return sarray_add((struct sorted_array *) ips, range);
}

bool
res6_empty(struct resources_ipv6 const *ips)
{
	return sarray_empty((struct sorted_array const *) ips);
}

bool
res6_contains_prefix(struct resources_ipv6 *ips,
    struct ipv6_prefix const *prefix)
{
	struct ipv6_range r;
	ptor(prefix, &r);
	return sarray_contains((struct sorted_array *) ips, &r);
}

bool
res6_contains_range(struct resources_ipv6 *ips, struct ipv6_range const *range)
{
	return sarray_contains((struct sorted_array *) ips, range);
}
