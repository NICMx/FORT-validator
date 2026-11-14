#include "resource/ip4.h"

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

enum resource_cmp_result
res4_add_prefix(struct resources_ipv4 *ips, struct ipv4_prefix const *prefix)
{
	struct r4_node n;
	pton(prefix, &n);
	return sarray_add((struct sorted_array *) ips, &n);
}

enum resource_cmp_result
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

static void
print_addr(uint32_t addr)
{
	char buf[INET_ADDRSTRLEN];
	printf("%s", inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN));
}

static int
print_node(void *_range, void *_first)
{
	struct r4_node *node = _range;
	bool *first = _first;

	if (!(*first))
		printf(", ");
	*first = false;

	if (node->min == node->max) {
		print_addr(node->min);
	} else {
		print_addr(node->min);
		printf("-");
		print_addr(node->max);
	}

	return 0;
}

void
res4_print(struct resources_ipv4 *ips)
{
	bool first;

	if (!ips) {
		printf("null");
		return;
	}

	first = true;
	sarray_foreach((struct sorted_array *) ips, print_node, &first);
}
