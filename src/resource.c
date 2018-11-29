#include "resource.h"

#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "address.h"
#include "log.h"
#include "sorted_array.h"

struct resource4 {
	struct ipv4_prefix prefix;
};

struct resource6 {
	struct ipv6_prefix prefix;
};

struct resource_asn {
	ASId_t min;
	ASId_t max;
};

/* The resources we extracted from one certificate. */
struct resources {
	struct sorted_array *ip4s;
	struct sorted_array *ip6s;
	struct sorted_array *asns;

	/*
	 * Used by restack. Points to the resources of the parent certificate.
	 */
	SLIST_ENTRY(resources) next;
};

/*
 * "Resource stack". It's a chain of resources, to complement a chain of
 * certificates.
 */
SLIST_HEAD(restack, resources);

static enum sarray_comparison
ip4_cmp(void *arg1, void *arg2)
{
	struct ipv4_prefix *p1 = &((struct resource4 *) arg1)->prefix;
	struct ipv4_prefix *p2 = &((struct resource4 *) arg2)->prefix;
	uint32_t a1;
	uint32_t a2;

	if (p1->addr.s_addr == p2->addr.s_addr && p1->len == p2->len)
		return SACMP_EQUAL;
	if (prefix4_contains(p1, p2))
		return SACMP_CHILD;
	if (prefix4_contains(p2, p1))
		return SACMP_PARENT;

	a1 = ntohl(p1->addr.s_addr);
	a2 = ntohl(p2->addr.s_addr);
	if (a1 < a2)
		return SACMP_RIGHT;
	if (a2 < a1)
		return SACMP_LEFT;

	/* TODO Actually an error. Do something about it? */
	return SACMP_INTERSECTION;
}

static enum sarray_comparison
ip6_cmp(void *arg1, void *arg2)
{
	struct ipv6_prefix *p1 = &((struct resource6 *) arg1)->prefix;
	struct ipv6_prefix *p2 = &((struct resource6 *) arg2)->prefix;
	struct in6_addr *a1 = &p1->addr;
	struct in6_addr *a2 = &p2->addr;
	uint32_t q1;
	uint32_t q2;
	unsigned int q;

	if (memcmp(a1, a2, sizeof(*a1)) == 0 && p1->len == p2->len)
		return SACMP_EQUAL;
	if (prefix6_contains(p1, p2))
		return SACMP_CHILD;
	if (prefix6_contains(p2, p1))
		return SACMP_PARENT;

	for (q = 0; q < 4; q++) {
		q1 = ntohl(p1->addr.s6_addr32[q]);
		q2 = ntohl(p2->addr.s6_addr32[q]);
		if (q1 < q2)
			return SACMP_RIGHT;
		if (q2 < q1)
			return SACMP_LEFT;
	}

	/* TODO Actually an error. Do something about it? */
	return SACMP_INTERSECTION;
}

static enum sarray_comparison
asn_cmp(void *arg1, void *arg2)
{
	struct resource_asn *asn1 = arg1;
	struct resource_asn *asn2 = arg2;

	if (asn1->min == asn2->min && asn1->max == asn2->max)
		return SACMP_EQUAL;
	if (asn1->min <= asn2->min && asn2->max <= asn1->max)
		return SACMP_CHILD;
	if (asn2->min <= asn1->min && asn1->max <= asn2->max)
		return SACMP_PARENT;
	if (asn1->max < asn2->min)
		return SACMP_RIGHT;
	if (asn2->max < asn1->min)
		return SACMP_LEFT;

	return SACMP_INTERSECTION;
}

SARRAY_API(r4array, resource4, ip4_cmp)
SARRAY_API(r6array, resource6, ip6_cmp)
SARRAY_API(asnarray, resource_asn, asn_cmp)

struct resources *
resources_create(void)
{
	struct resources *result;

	result = malloc(sizeof(struct resources));
	if (result == NULL) {
		pr_err("Out of memory.");
		return NULL;
	}

	result->ip4s = NULL;
	result->ip6s = NULL;
	result->asns = NULL;

	return result;
}

void
resources_destroy(struct resources *resources)
{
	if (resources->ip4s != NULL)
		r4array_put(resources->ip4s);
	if (resources->ip6s != NULL)
		r6array_put(resources->ip6s);
	if (resources->asns != NULL)
		asnarray_put(resources->asns);
	free(resources);
}

static int
get_addr_family(OCTET_STRING_t *octets)
{
	if (octets->size != 2) {
		pr_err("Address family has %d octets. (2 expected.)",
		    octets->size);
		return -1;
	}

	if (octets->buf[0] != 0)
		goto unknown;
	switch (octets->buf[1]) {
	case 1:
		return AF_INET;
	case 2:
		return AF_INET6;
	}

unknown:
	pr_err("Address family has unknown value 0x%02x%02x.", octets->buf[0],
	    octets->buf[1]);
	return -1;
}

static void
pr_debug_prefix(int family, void *addr, int length)
{
#ifdef DEBUG
	char buffer[INET6_ADDRSTRLEN];
	char const *string;

	string = inet_ntop(family, addr, buffer, sizeof(buffer));
	if (string != NULL)
		pr_debug("Prefix: %s/%u", string, length);
	else {
		pr_debug("Prefix: (Cannot convert to string. Errcode %d)",
		    errno);
	}
#endif
}

static int
inherit_aors(struct resources *resources, int family, struct resources *parent)
{
	switch (family) {
	case AF_INET:
		if (resources->ip4s != NULL) {
			pr_err("Oh noes4"); /* TODO */
			return -EINVAL;
		}
		if (parent->ip4s == NULL) {
			pr_err("Certificate inherits IPv4 resources from parent, but parent lacks IPv4 resources.");
			return -EINVAL;
		}
		resources->ip4s = parent->ip4s;
		r4array_get(resources->ip4s);
		return 0;

	case AF_INET6:
		if (resources->ip6s != NULL) {
			pr_err("Oh noes6"); /* TODO */
			return -EINVAL;
		}
		if (parent->ip6s == NULL) {
			pr_err("Certificate inherits IPv6 resources from parent, but parent lacks IPv6 resources.");
			return -EINVAL;
		}
		resources->ip6s = parent->ip6s;
		r6array_get(resources->ip6s);
		return 0;
	}

	pr_err("Programming error: Unknown IP family: %d", family);
	return -EINVAL;
}

static int
decode_prefix4(BIT_STRING_t *str, struct ipv4_prefix *result)
{
	/* TODO validate bits unused and stuff */
	if (str->size > 4) {
		pr_err("IPv4 address has too many octets. (%u)", str->size);
		return -EINVAL;
	}

	memset(&result->addr, 0, sizeof(result->addr));
	memcpy(&result->addr, str->buf, str->size);
	result->len = 8 * str->size - str->bits_unused;
	return 0;
}

static int
decode_prefix6(BIT_STRING_t *str, struct ipv6_prefix *result)
{
	if (str->size > 16) {
		pr_err("IPv6 address has too many octets. (%u)", str->size);
		return -EINVAL;
	}

	memset(&result->addr, 0, sizeof(result->addr));
	memcpy(&result->addr, str->buf, str->size);
	result->len = 8 * str->size - str->bits_unused;
	return 0;
}

static int
add_prefix4(struct resources *resources, IPAddress2_t *addr,
    struct resources *parent)
{
	struct resource4 r4;
	int error;

	error = decode_prefix4(addr, &r4.prefix);
	if (error)
		return error;

	if (parent && !r4array_contains(parent->ip4s, &r4)) {
		pr_err("Parent certificate doesn't own child's IPv4 resource.");
		return -EINVAL;
	}

	if (resources->ip4s == NULL) {
		resources->ip4s = r4array_create();
		if (resources->ip4s == NULL) {
			pr_err("Out of memory.");
			return -ENOMEM;
		}
	}

	error = r4array_add(resources->ip4s, &r4);
	if (error)
		return error; /* TODO error message */

	pr_debug_prefix(AF_INET, &r4.prefix.addr, r4.prefix.len);
	return 0;
}

static int
add_prefix6(struct resources *resources, IPAddress2_t *addr,
    struct resources *parent)
{
	struct resource6 r6;
	int error;

	error = decode_prefix6(addr, &r6.prefix);
	if (error)
		return error;

	if (parent && !r6array_contains(parent->ip6s, &r6)) {
		pr_err("Parent certificate doesn't own child's IPv6 resource.");
		return -EINVAL;
	}

	if (resources->ip6s == NULL) {
		resources->ip6s = r6array_create();
		if (resources->ip6s == NULL) {
			pr_err("Out of memory.");
			return -ENOMEM;
		}
	}

	error = r6array_add(resources->ip6s, &r6);
	if (error)
		return error; /* TODO error message */

	pr_debug_prefix(AF_INET6, &r6.prefix.addr, r6.prefix.len);
	return 0;
}

static int
add_prefix(struct resources *resources, int family, IPAddress2_t *addr,
    struct resources *parent)
{
	switch (family) {
	case AF_INET:
		return add_prefix4(resources, addr, parent);
	case AF_INET6:
		return add_prefix6(resources, addr, parent);
	}

	pr_err("Unknown address family: %d", family);
	return 0;
}

static int
add_aors(struct resources *resources, int family,
    struct IPAddressChoice__addressesOrRanges *aors, struct resources *parent)
{
	struct IPAddressOrRange *aor;
	int i;
	int error = 0;

	/*
	 * TODO The addressPrefix and addressRange elements MUST be sorted
	 * using the binary representation of (...)
	 * TODO Any pair of IPAddressOrRange choices in
	 * an extension MUST NOT overlap each other.
	 */

	for (i = 0; i < aors->list.count; i++) {
		aor = aors->list.array[i];
		switch (aor->present) {
		case IPAddressOrRange_PR_addressPrefix:
			error = add_prefix(resources, family,
			    &aor->choice.addressPrefix, parent);
			if (error)
				return error;
			break;
		case IPAddressOrRange_PR_addressRange:
			/*
			 * We're definitely not supposed to support this.
			 *
			 * rfc3779#section-2.2.3.7 says "This specification
			 * requires that any range of addresses that can be
			 * encoded as a prefix MUST be encoded using an
			 * IPAddress element (...), and any range that cannot be
			 * encoded as a prefix MUST be encoded using an
			 * IPAddressRange (...).
			 *
			 * rfc6482#section-3.3 says "Note that the syntax here
			 * is more restrictive than that used in the IP address
			 * delegation extension defined in RFC 3779. That
			 * extension can represent arbitrary address ranges,
			 * whereas ROAs need to represent only prefixes."
			 */
			pr_err("IPAddressOrRange is a range. This is unsupported.");
			return -EINVAL;
		case IPAddressOrRange_PR_NOTHING:
			/* rfc3779#section-2.2.3.7 */
			pr_err("Unknown IPAddressOrRange type: %d",
			    aor->present);
			break;
		}
	}

	return 0;
}

int
resources_add_ip(struct resources *resources, struct IPAddressFamily *obj,
    struct resources *parent)
{
	int family;

	family = get_addr_family(&obj->addressFamily);
	if (family == -1)
		return -EINVAL;

	switch (obj->ipAddressChoice.present) {
	case IPAddressChoice_PR_NOTHING:
		break;
	case IPAddressChoice_PR_inherit:
		return inherit_aors(resources, family, parent);
	case IPAddressChoice_PR_addressesOrRanges:
		return add_aors(resources, family,
		    &obj->ipAddressChoice.choice.addressesOrRanges, parent);
	}

	/* rfc3779#section-2.2.3.4 */
	pr_err("Unknown ipAddressChoice type: %d",
	    obj->ipAddressChoice.present);
	return -EINVAL;
}

static int
inherit_asiors(struct resources *resources, struct resources *parent)
{
	if (resources->asns != NULL) {
		pr_err("Oh noesa"); /* TODO */
		return -EINVAL;
	}
	if (parent->asns == NULL) {
		pr_err("Certificate inherits ASN resources from parent, but parent lacks ASN resources.");
		return -EINVAL;
	}
	resources->asns = parent->asns;
	asnarray_get(resources->asns);
	return 0;
}

static int
add_asn(struct resources *resources, ASId_t min, ASId_t max,
    struct resources *parent)
{
	struct resource_asn ra;
	int error;

	if (resources->asns == NULL) {
		resources->asns = asnarray_create();
		if (resources->asns == NULL) {
			pr_err("Out of memory.");
			return -ENOMEM;
		}
	}

	ra.min = min;
	ra.max = max;
	error = asnarray_add(resources->asns, &ra);
	if (error)
		return error; /* TODO error msg */

	if (min == max)
		pr_debug("ASN: %ld", min);
	else
		pr_debug("ASN: %ld-%ld", min, max);
	return 0;
}

static int
add_asior(struct resources *resources, struct ASIdOrRange *obj,
    struct resources *parent)
{
	switch (obj->present) {
	case ASIdOrRange_PR_NOTHING:
		break;
	case ASIdOrRange_PR_id:
		return add_asn(resources, obj->choice.id, obj->choice.id,
		    parent);
	case ASIdOrRange_PR_range:
		return add_asn(resources, obj->choice.range.min,
		    obj->choice.range.max, parent);
	}

	pr_err("Unknown ASIdOrRange type: %d", obj->present);
	return -EINVAL;
}

int
resources_add_asn(struct resources *resources, struct ASIdentifiers *ids,
    struct resources *parent)
{
	struct ASIdentifierChoice__asIdsOrRanges *iors;
	int i;
	int error;

	if (ids->asnum == NULL) {
		pr_err("ASN extension lacks 'asnum' element.");
		return -EINVAL;
	}
	if (ids->rdi != NULL) {
		pr_err("ASN extension has 'rdi' element. (Prohibited by RFC6487)");
		return -EINVAL;
	}

	switch (ids->asnum->present) {
	case ASIdentifierChoice_PR_inherit:
		return inherit_asiors(resources, parent);
	case ASIdentifierChoice_PR_asIdsOrRanges:
		/*
		 * TODO
		 * Any pair of items in the asIdsOrRanges SEQUENCE MUST NOT
		 * overlap. Any contiguous series of AS identifiers MUST be
		 * combined into a single range whenever possible. The AS
		 * identifiers in the asIdsOrRanges element MUST be sorted by
		 * increasing numeric value.
		 */
		iors = &ids->asnum->choice.asIdsOrRanges;
		for (i = 0; i < iors->list.count; i++) {
			error = add_asior(resources, iors->list.array[i],
			    parent);
			if (error)
				return error;
		}
		return 0;

	case ASIdentifierChoice_PR_NOTHING:
		break;
	}

	pr_err("Unknown ASIdentifierChoice: %d", ids->asnum->present);
	return -EINVAL;
}

int
resources_join(struct resources *r1, struct resources *r2)
{
	int error;

	if (r1->ip4s != NULL) {
		error = r4array_join(r1->ip4s, r2->ip4s);
		if (error)
			return error;
	}
	if (r1->ip6s != NULL) {
		error = r6array_join(r1->ip6s, r2->ip6s);
		if (error)
			return error;
	}
	if (r1->asns != NULL) {
		error = asnarray_join(r1->asns, r2->asns);
		if (error)
			return error;
	}

	return 0;
}

struct restack *
restack_create(void)
{
	struct restack *result;

	result = malloc(sizeof(struct restack));
	if (result == NULL) {
		pr_err("Out of memory.");
		return NULL;
	}

	SLIST_INIT(result);
	return result;
}

void
restack_destroy(struct restack *stack)
{
	struct resources *resources;
	unsigned int r = 0;

	while (!SLIST_EMPTY(stack)) {
		resources = SLIST_FIRST(stack);
		SLIST_REMOVE_HEAD(stack, next);
		resources_destroy(resources);
		r++;
	}

	free(stack);
	pr_debug("Deleted %u resources from the stack.", r);
}

void
restack_push(struct restack *stack, struct resources *new)
{
	SLIST_INSERT_HEAD(stack, new, next);
}

struct resources *
restack_pop(struct restack *stack)
{
	struct resources *res;

	res = SLIST_FIRST(stack);
	if (res != NULL) {
		SLIST_REMOVE_HEAD(stack, next);
		SLIST_NEXT(res, next) = NULL;
	}

	return res;
}

struct resources *
restack_peek(struct restack *stack)
{
	return SLIST_FIRST(stack);
}
