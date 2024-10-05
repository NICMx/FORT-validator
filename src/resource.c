#include "resource.h"

#include <errno.h>

#include "alloc.h"
#include "log.h"
#include "resource/ip4.h"
#include "resource/ip6.h"
#include "thread_var.h"
#include "types/sorted_array.h"

/* The resources we extracted from one certificate. */
struct resources {
	struct resources_ipv4 *ip4s;
	struct resources_ipv6 *ip6s;
	struct resources_asn *asns;
	enum rpki_policy policy;
	/**
	 * Should we ban the embedded certificate from defining its own
	 * resources? (Otherwise it's only allowed to inherit them.)
	 *
	 * This should not be implemented as a separate policy, because @policy
	 * still has to decide whether the certificate is allowed to contain
	 * classic or revised extensions.
	 */
	bool force_inherit;
};

struct resources *
resources_create(enum rpki_policy policy, bool force_inherit)
{
	struct resources *result;

	result = pmalloc(sizeof(struct resources));

	result->ip4s = NULL;
	result->ip6s = NULL;
	result->asns = NULL;
	result->policy = policy;
	result->force_inherit = force_inherit;

	return result;
}

void
resources_destroy(struct resources *resources)
{
	if (resources->ip4s != NULL)
		res4_put(resources->ip4s);
	if (resources->ip6s != NULL)
		res6_put(resources->ip6s);
	if (resources->asns != NULL)
		rasn_put(resources->asns);
	free(resources);
}

int
get_addr_family(OCTET_STRING_t *octets)
{
	if (octets->size != 2) {
		pr_val_err("Address family has %zu octets. (2 expected.)",
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
	pr_val_err("Address family has unknown value 0x%02x%02x.", octets->buf[0],
	    octets->buf[1]);
	return -1;
}

static int
inherit_aors(struct resources *resources, struct resources *parent, int family)
{
	if (parent == NULL)
		return pr_val_err("Root certificate is trying to inherit IP resources from a parent.");

	switch (family) {
	case AF_INET:
		if (resources->ip4s != NULL)
			return pr_val_err("Certificate inherits IPv4 resources while also defining others of its own.");
		resources->ip4s = parent->ip4s;
		if (resources->ip4s != NULL)
			res4_get(resources->ip4s);
		pr_val_debug("<Inherit IPv4>");
		return 0;

	case AF_INET6:
		if (resources->ip6s != NULL)
			return pr_val_err("Certificate inherits IPv6 resources while also defining others of its own.");
		resources->ip6s = parent->ip6s;
		if (resources->ip6s != NULL)
			res6_get(resources->ip6s);
		pr_val_debug("<Inherit IPv6>");
		return 0;
	}

	pr_crit("Unknown address family '%d'", family);
	return EINVAL; /* Warning shutupper */
}

static int
add_prefix4(struct resources *resources, struct resources *parent,
    IPAddress_t *addr)
{
	struct ipv4_prefix prefix;
	int error;

	if (parent && (resources->ip4s == parent->ip4s))
		return pr_val_err("Certificate defines IPv4 prefixes while also inheriting his parent's.");

	error = prefix4_decode(addr, &prefix);
	if (error)
		return error;

	if (parent && !res4_contains_prefix(parent->ip4s, &prefix)) {
		switch (resources->policy) {
		case RPKI_POLICY_RFC6484:
			return pr_val_err("Parent certificate doesn't own IPv4 prefix '%s/%u'.",
			    v4addr2str(&prefix.addr), prefix.len);
		case RPKI_POLICY_RFC8360:
			return pr_val_warn("Certificate is overclaiming the IPv4 prefix '%s/%u'.",
			    v4addr2str(&prefix.addr), prefix.len);
		}
	}

	if (resources->ip4s == NULL)
		resources->ip4s = res4_create();

	error = res4_add_prefix(resources->ip4s, &prefix);
	if (error) {
		pr_val_err("Error adding IPv4 prefix '%s/%u' to certificate resources: %s",
		    v4addr2str(&prefix.addr), prefix.len,
		    sarray_err2str(error));
		return error;
	}

	pr_val_debug("Prefix: %s/%u", v4addr2str(&prefix.addr), prefix.len);
	return 0;
}

static int
add_prefix6(struct resources *resources, struct resources *parent,
    IPAddress_t *addr)
{
	struct ipv6_prefix prefix;
	int error;

	if (parent && (resources->ip6s == parent->ip6s))
		return pr_val_err("Certificate defines IPv6 prefixes while also inheriting his parent's.");

	error = prefix6_decode(addr, &prefix);
	if (error)
		return error;

	if (parent && !res6_contains_prefix(parent->ip6s, &prefix)) {
		switch (resources->policy) {
		case RPKI_POLICY_RFC6484:
			return pr_val_err("Parent certificate doesn't own IPv6 prefix '%s/%u'.",
			    v6addr2str(&prefix.addr), prefix.len);
		case RPKI_POLICY_RFC8360:
			return pr_val_warn("Certificate is overclaiming the IPv6 prefix '%s/%u'.",
			    v6addr2str(&prefix.addr), prefix.len);
		}
	}

	if (resources->ip6s == NULL)
		resources->ip6s = res6_create();

	error = res6_add_prefix(resources->ip6s, &prefix);
	if (error) {
		pr_val_err("Error adding IPv6 prefix '%s/%u' to certificate resources: %s",
		    v6addr2str(&prefix.addr), prefix.len,
		    sarray_err2str(error));
		return error;
	}

	pr_val_debug("Prefix: %s/%u", v6addr2str(&prefix.addr), prefix.len);
	return 0;
}

static int
add_prefix(struct resources *resources, struct resources *parent,
    int family, IPAddress_t *addr)
{
	switch (family) {
	case AF_INET:
		return add_prefix4(resources, parent, addr);
	case AF_INET6:
		return add_prefix6(resources, parent, addr);
	}

	pr_crit("Unknown address family '%d'", family);
	return EINVAL; /* Warning shutupper */
}

static int
add_range4(struct resources *resources, struct resources *parent,
    IPAddressRange_t *input)
{
	struct ipv4_range range;
	int error;

	if (parent && (resources->ip4s == parent->ip4s))
		return pr_val_err("Certificate defines IPv4 ranges while also inheriting his parent's.");

	error = range4_decode(input, &range);
	if (error)
		return error;

	if (parent && !res4_contains_range(parent->ip4s, &range)) {
		switch (resources->policy) {
		case RPKI_POLICY_RFC6484:
			return pr_val_err("Parent certificate doesn't own IPv4 range '%s-%s'.",
			    v4addr2str(&range.min), v4addr2str2(&range.max));
		case RPKI_POLICY_RFC8360:
			return pr_val_warn("Certificate is overclaiming the IPv4 range '%s-%s'.",
			    v4addr2str(&range.min), v4addr2str2(&range.max));
		}
	}

	if (resources->ip4s == NULL)
		resources->ip4s = res4_create();

	error = res4_add_range(resources->ip4s, &range);
	if (error) {
		pr_val_err("Error adding IPv4 range '%s-%s' to certificate resources: %s",
		    v4addr2str(&range.min), v4addr2str2(&range.max),
		    sarray_err2str(error));
		return error;
	}

	pr_val_debug("Range: %s-%s", v4addr2str(&range.min),
	    v4addr2str2(&range.max));
	return 0;
}

static int
add_range6(struct resources *resources, struct resources *parent,
    IPAddressRange_t *input)
{
	struct ipv6_range range;
	int error;

	if (parent && (resources->ip6s == parent->ip6s))
		return pr_val_err("Certificate defines IPv6 ranges while also inheriting his parent's.");

	error = range6_decode(input, &range);
	if (error)
		return error;

	if (parent && !res6_contains_range(parent->ip6s, &range)) {
		switch (resources->policy) {
		case RPKI_POLICY_RFC6484:
			return pr_val_err("Parent certificate doesn't own IPv6 range '%s-%s'.",
			    v6addr2str(&range.min), v6addr2str2(&range.max));
		case RPKI_POLICY_RFC8360:
			return pr_val_warn("Certificate is overclaiming the IPv6 range '%s-%s'.",
			    v6addr2str(&range.min), v6addr2str2(&range.max));
		}
	}

	if (resources->ip6s == NULL)
		resources->ip6s = res6_create();

	error = res6_add_range(resources->ip6s, &range);
	if (error) {
		pr_val_err("Error adding IPv6 range '%s-%s' to certificate resources: %s",
		    v6addr2str(&range.min), v6addr2str2(&range.max),
		    sarray_err2str(error));
		return error;
	}

	pr_val_debug("Range: %s-%s", v6addr2str(&range.min),
	    v6addr2str2(&range.max));
	return 0;
}

static int
add_range(struct resources *resources, struct resources *parent,
    int family, IPAddressRange_t *range)
{
	switch (family) {
	case AF_INET:
		return add_range4(resources, parent, range);
	case AF_INET6:
		return add_range6(resources, parent, range);
	}

	pr_crit("Unknown address family '%d'", family);
	return EINVAL; /* Warning shutupper */
}

static int
add_aors(struct resources *resources, struct resources *parent, int family,
    struct IPAddressChoice__addressesOrRanges *aors)
{
	struct IPAddressOrRange *aor;
	int i;
	int error;

	if (resources->force_inherit)
		return pr_val_err("Certificate is only allowed to inherit resources, but defines its own IP addresses or ranges.");
	if (aors->list.count == 0)
		return pr_val_err("IP extension's set of IP address records is empty.");

	for (i = 0; i < aors->list.count; i++) {
		aor = aors->list.array[i];
		switch (aor->present) {
		case IPAddressOrRange_PR_addressPrefix:
			error = add_prefix(resources, parent, family,
			    &aor->choice.addressPrefix);
			if (error)
				return error;
			break;
		case IPAddressOrRange_PR_addressRange:
			error = add_range(resources, parent, family,
			    &aor->choice.addressRange);
			if (error)
				return error;
			break;
		case IPAddressOrRange_PR_NOTHING:
			/* rfc3779#section-2.2.3.7 */
			return pr_val_err("Unknown IPAddressOrRange type: %u",
			    aor->present);
		}
	}

	return 0;
}

int
resources_add_ip(struct resources *resources, struct resources *parent,
    struct IPAddressFamily *obj)
{
	int family;

	family = get_addr_family(&obj->addressFamily);
	if (family == -1)
		return -EINVAL;

	switch (obj->ipAddressChoice.present) {
	case IPAddressChoice_PR_NOTHING:
		break;
	case IPAddressChoice_PR_inherit:
		return inherit_aors(resources, parent, family);
	case IPAddressChoice_PR_addressesOrRanges:
		return add_aors(resources, parent, family,
		    &obj->ipAddressChoice.choice.addressesOrRanges);
	}

	/* rfc3779#section-2.2.3.4 */
	return pr_val_err("Unknown ipAddressChoice type: %u",
	    obj->ipAddressChoice.present);
}

static int
inherit_asiors(struct resources *resources, struct resources *parent)
{
	if (parent == NULL)
		return pr_val_err("Root certificate is trying to inherit AS resources from a parent.");

	if (resources->asns != NULL)
		return pr_val_err("Certificate inherits ASN resources while also defining others of its own.");

	resources->asns = parent->asns;
	if (resources->asns != NULL)
		rasn_get(resources->asns);
	pr_val_debug("<Inherit ASN>");
	return 0;
}

static int
ASId2u32(ASId_t *as_id, uint32_t *result)
{
	static const unsigned long ASN_MAX = UINT32_MAX;
	unsigned long ulong;
	int error;

	error = asn_INTEGER2ulong(as_id, &ulong);
	if (error) {
		if (errno) {
			pr_val_err("Error converting ASN value: %s",
			    strerror(errno));
		}
		return pr_val_err("ASN value is not a valid unsigned long");
	}

	if (ulong > ASN_MAX) {
		return pr_val_err("ASN value '%lu' is out of bounds. (0-%lu)",
		    ulong, ASN_MAX);
	}

	*result = ulong;
	return 0;
}

static int
add_asn(struct resources *resources, struct asn_range const *asns,
    struct resources *parent)
{
	int error;

	if (asns->min > asns->max) {
		return pr_val_err("The ASN range %u-%u is inverted.",
		    asns->min, asns->max);
	}

	if (parent && !rasn_contains(parent->asns, asns)) {
		switch (resources->policy) {
		case RPKI_POLICY_RFC6484:
			return pr_val_err("Parent certificate doesn't own ASN range '%u-%u'.",
			    asns->min, asns->max);
		case RPKI_POLICY_RFC8360:
			return pr_val_warn("Certificate is overclaiming the ASN range '%u-%u'.",
			    asns->min, asns->max);
		}
	}

	if (resources->asns == NULL)
		resources->asns = rasn_create();

	error = rasn_add(resources->asns, asns);
	if (error){
		pr_val_err("Error adding ASN range '%u-%u' to certificate resources: %s",
		    asns->min, asns->max, sarray_err2str(error));
		return error;
	}

	if (asns->min == asns->max)
		pr_val_debug("ASN: %u", asns->min);
	else
		pr_val_debug("ASN: %u-%u", asns->min, asns->max);
	return 0;
}

static int
add_asior(struct resources *resources, struct resources *parent,
    struct ASIdOrRange *obj)
{
	struct asn_range asns;
	int error;

	if (parent && (resources->asns == parent->asns))
		return pr_val_err("Certificate defines ASN resources while also inheriting his parent's.");

	switch (obj->present) {
	case ASIdOrRange_PR_NOTHING:
		break;

	case ASIdOrRange_PR_id:
		error = ASId2u32(&obj->choice.id, &asns.min);
		if (error)
			return error;
		asns.max = asns.min;
		return add_asn(resources, &asns, parent);

	case ASIdOrRange_PR_range:
		error = ASId2u32(&obj->choice.range.min, &asns.min);
		if (error)
			return error;
		error = ASId2u32(&obj->choice.range.max, &asns.max);
		if (error)
			return error;
		return add_asn(resources, &asns, parent);
	}

	return pr_val_err("Unknown ASIdOrRange type: %u", obj->present);
}

static int
add_asiors(struct resources *resources, struct resources *parent,
    struct ASIdentifiers *ids)
{
	struct ASIdentifierChoice__asIdsOrRanges *iors;
	int i;
	int error;

	if (resources->force_inherit)
		return pr_val_err("Certificate is only allowed to inherit resources, but defines its own AS numbers.");

	iors = &ids->asnum->choice.asIdsOrRanges;
	if (iors->list.count == 0)
		return pr_val_err("AS extension's set of AS number records is empty.");

	for (i = 0; i < iors->list.count; i++) {
		error = add_asior(resources, parent, iors->list.array[i]);
		if (error)
			return error;
	}

	return 0;
}

int
resources_add_asn(struct resources *resources, struct resources *parent,
    struct ASIdentifiers *ids, bool allow_inherit)
{
	if (ids->asnum == NULL)
		return pr_val_err("ASN extension lacks 'asnum' element.");
	if (ids->rdi != NULL)
		return pr_val_err("ASN extension has 'rdi' element. (Prohibited by RFC6487)");

	switch (ids->asnum->present) {
	case ASIdentifierChoice_PR_inherit:
		if (!allow_inherit)
			return pr_val_err("ASIdentifierChoice %u isn't allowed",
			    ids->asnum->present);
		return inherit_asiors(resources, parent);
	case ASIdentifierChoice_PR_asIdsOrRanges:
		return add_asiors(resources, parent, ids);
	case ASIdentifierChoice_PR_NOTHING:
		break;
	}

	return pr_val_err("Unknown ASIdentifierChoice: %u", ids->asnum->present);
}

bool
resources_empty(struct resources *res)
{
	return rasn_empty(res->asns)
	    && res4_empty(res->ip4s)
	    && res6_empty(res->ip6s);
}

bool
resources_contains_asns(struct resources *res, struct asn_range const *range)
{
	return rasn_contains(res->asns, range);
}

bool
resources_contains_ipv4(struct resources *res, struct ipv4_prefix const *prefix)
{
	return res4_contains_prefix(res->ip4s, prefix);
}

bool
resources_contains_ipv6(struct resources *res, struct ipv6_prefix const *prefix)
{
	return res6_contains_prefix(res->ip6s, prefix);
}

void
resources_set_policy(struct resources *res, enum rpki_policy policy)
{
	res->policy = policy;
}

int
resources_foreach_asn(struct resources *res, foreach_asn_cb cb, void *arg)
{
	return rasn_foreach(res->asns, cb, arg);
}
