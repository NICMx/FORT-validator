#include "types/vrp.h"

#include "log.h"
#include "types/address.h"

bool
vrp_equals(struct vrp const *a, struct vrp const *b)
{
	if ((a->addr_fam != b->addr_fam) ||
	    (a->asn != b->asn) ||
	    (a->prefix_length != b->prefix_length) ||
	    (a->max_prefix_length != b->max_prefix_length))
		return false;

	switch (a->addr_fam) {
	case AF_INET:
		return a->prefix.v4.s_addr == b->prefix.v4.s_addr;
	case AF_INET6:
		return addr6_equals(&a->prefix.v6, &b->prefix.v6);
	}

	pr_crit("Unknown address family: %u", a->addr_fam);
	return false; /* Warning shutupper */
}

/* Checks if a's prefix equals or covers b's prefix */
bool
vrp_prefix_cov(struct vrp const *a, struct vrp const *b)
{
	if (a->addr_fam != b->addr_fam)
		return false;

	switch (a->addr_fam) {
	case AF_INET:
		return ipv4_covered(&a->prefix.v4, a->prefix_length, &b->prefix.v4)
		    && (a->prefix_length <= b->prefix_length);
	case AF_INET6:
		return ipv6_covered(&a->prefix.v6, a->prefix_length, &b->prefix.v6)
		    && (a->prefix_length <= b->prefix_length);
	}

	pr_crit("Unknown address family: %u", a->addr_fam);
	return false; /* Warning shutupper */
}

int
vrp_print(struct vrp const *roa, void *arg)
{
	char buffer[INET6_ADDRSTRLEN];
	printf("- [ROA ASN:%u Prefix:%s/(%u-%u)]\n", roa->asn,
	    inet_ntop(roa->addr_fam, &roa->prefix, buffer, INET6_ADDRSTRLEN),
	    roa->prefix_length, roa->max_prefix_length);
	return 0;
}
