#include "resource.h"

#include <errno.h>
#include <arpa/inet.h>

#include "address.h"
#include "log.h"
#include "sorted_array.h"
#include "thread_var.h"
#include "resource/ip4.h"
#include "resource/ip6.h"
#include "resource/asn.h"

/* The resources we extracted from one certificate. */
struct resources {
	struct resources_ipv4 *ip4s;
	struct resources_ipv6 *ip6s;
	struct resources_asn *asns;
};

struct resources *
resources_create(void)
{
	struct resources *result;

	result = malloc(sizeof(struct resources));
	if (result == NULL)
		return NULL;

	result->ip4s = NULL;
	result->ip6s = NULL;
	result->asns = NULL;

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

static struct resources *
get_parent_resources(void)
{
	struct validation *state = state_retrieve();
	return (state != NULL) ? validation_peek_resource(state) : NULL;
}

static void
pr_debug_ip_prefix(int family, void *addr, unsigned int length)
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

static void
pr_debug_range(int family, void *min, void *max)
{
#ifdef DEBUG
	char buffer_min[INET6_ADDRSTRLEN];
	char buffer_max[INET6_ADDRSTRLEN];
	char const *string_min;
	char const *string_max;

	string_min = inet_ntop(family, min, buffer_min, sizeof(buffer_min));
	if (string_min == NULL)
		goto fail;

	string_max = inet_ntop(family, max, buffer_max, sizeof(buffer_max));
	if (string_max == NULL)
		goto fail;

	pr_debug("Range: %s-%s", string_min, string_max);
	return;

fail:
	pr_debug("Range: (Cannot convert to string. Errcode %d)", errno);
#endif
}

static int
inherit_aors(struct resources *resources, int family)
{
	struct resources *parent;

	parent = get_parent_resources();
	if (parent == NULL)
		return pr_err("Certificate inherits IP resources, but parent does not define any resources.");

	switch (family) {
	case AF_INET:
		if (resources->ip4s != NULL)
			return pr_err("Certificate inherits IPv4 resources while also defining others of its own.");
		if (parent->ip4s == NULL)
			return pr_err("Certificate inherits IPv4 resources from parent, but parent lacks IPv4 resources.");
		resources->ip4s = parent->ip4s;
		res4_get(resources->ip4s);
		pr_debug("<Inherit IPv4>");
		return 0;

	case AF_INET6:
		if (resources->ip6s != NULL)
			return pr_err("Certificate inherits IPv6 resources while also defining others of its own.");
		if (parent->ip6s == NULL)
			return pr_err("Certificate inherits IPv6 resources from parent, but parent lacks IPv6 resources.");
		resources->ip6s = parent->ip6s;
		res6_get(resources->ip6s);
		pr_debug("<Inherit IPv6>");
		return 0;
	}

	return pr_crit("Unknown address family '%d'", family);
}

static int
add_prefix4(struct resources *resources, IPAddress2_t *addr)
{
	struct resources *parent;
	struct ipv4_prefix prefix;
	int error;

	parent = get_parent_resources();

	if ((parent != NULL) && (resources->ip4s == parent->ip4s))
		return pr_err("Certificate defines IPv4 prefixes while also inheriting his parent's.");

	error = prefix4_decode(addr, &prefix);
	if (error)
		return error;

	if (parent && !res4_contains_prefix(parent->ip4s, &prefix))
		return pr_err("Parent certificate doesn't own child's IPv4 resource.");

	if (resources->ip4s == NULL) {
		resources->ip4s = res4_create();
		if (resources->ip4s == NULL)
			return pr_enomem();
	}

	error = res4_add_prefix(resources->ip4s, &prefix);
	if (error) {
		pr_err("Error adding IPv4 prefix to certificate resources: %s",
		    sarray_err2str(error));
		return error;
	}

	pr_debug_ip_prefix(AF_INET, &prefix.addr, prefix.len);
	return 0;
}

static int
add_prefix6(struct resources *resources, IPAddress2_t *addr)
{
	struct resources *parent;
	struct ipv6_prefix prefix;
	int error;

	parent = get_parent_resources();

	if ((parent != NULL) && (resources->ip6s == parent->ip6s))
		return pr_err("Certificate defines IPv6 prefixes while also inheriting his parent's.");

	error = prefix6_decode(addr, &prefix);
	if (error)
		return error;

	if (parent && !res6_contains_prefix(parent->ip6s, &prefix))
		return pr_err("Parent certificate doesn't own child's IPv6 resource.");

	if (resources->ip6s == NULL) {
		resources->ip6s = res6_create();
		if (resources->ip6s == NULL)
			return pr_enomem();
	}

	error = res6_add_prefix(resources->ip6s, &prefix);
	if (error) {
		pr_err("Error adding IPv6 prefix to certificate resources: %s",
		    sarray_err2str(error));
		return error;
	}

	pr_debug_ip_prefix(AF_INET6, &prefix.addr, prefix.len);
	return 0;
}

static int
add_prefix(struct resources *resources, int family, IPAddress2_t *addr)
{
	switch (family) {
	case AF_INET:
		return add_prefix4(resources, addr);
	case AF_INET6:
		return add_prefix6(resources, addr);
	}

	return pr_crit("Unknown address family '%d'", family);
}

static int
add_range4(struct resources *resources, IPAddressRange_t *input)
{
	struct resources *parent;
	struct ipv4_range range;
	int error;

	parent = get_parent_resources();

	if ((parent != NULL) && (resources->ip4s == parent->ip4s))
		return pr_err("Certificate defines IPv4 ranges while also inheriting his parent's.");

	error = range4_decode(input, &range);
	if (error)
		return error;

	if (parent && !res4_contains_range(parent->ip4s, &range))
		return pr_err("Parent certificate doesn't own child's IPv4 resource.");

	if (resources->ip4s == NULL) {
		resources->ip4s = res4_create();
		if (resources->ip4s == NULL)
			return pr_enomem();
	}

	error = res4_add_range(resources->ip4s, &range);
	if (error) {
		pr_err("Error adding IPv4 range to certificate resources: %s",
		    sarray_err2str(error));
		return error;
	}

	pr_debug_range(AF_INET, &range.min, &range.max);
	return 0;
}

static int
add_range6(struct resources *resources, IPAddressRange_t *input)
{
	struct resources *parent;
	struct ipv6_range range;
	int error;

	parent = get_parent_resources();

	if ((parent != NULL) && (resources->ip6s == parent->ip6s))
		return pr_err("Certificate defines IPv6 ranges while also inheriting his parent's.");

	error = range6_decode(input, &range);
	if (error)
		return error;

	if (parent && !res6_contains_range(parent->ip6s, &range))
		return pr_err("Parent certificate doesn't own child's IPv6 resource.");

	if (resources->ip6s == NULL) {
		resources->ip6s = res6_create();
		if (resources->ip6s == NULL)
			return pr_enomem();
	}

	error = res6_add_range(resources->ip6s, &range);
	if (error) {
		pr_err("Error adding IPv6 range to certificate resources: %s",
		    sarray_err2str(error));
		return error;
	}

	pr_debug_range(AF_INET6, &range.min, &range.max);
	return 0;
}

static int
add_range(struct resources *resources, int family, IPAddressRange_t *range)
{
	switch (family) {
	case AF_INET:
		return add_range4(resources, range);
	case AF_INET6:
		return add_range6(resources, range);
	}

	return pr_crit("Unknown address family '%d'", family);
}

static int
add_aors(struct resources *resources, int family,
    struct IPAddressChoice__addressesOrRanges *aors)
{
	struct IPAddressOrRange *aor;
	int i;
	int error = 0;

	for (i = 0; i < aors->list.count; i++) {
		aor = aors->list.array[i];
		switch (aor->present) {
		case IPAddressOrRange_PR_addressPrefix:
			error = add_prefix(resources, family,
			    &aor->choice.addressPrefix);
			if (error)
				return error;
			break;
		case IPAddressOrRange_PR_addressRange:
			error = add_range(resources, family,
			    &aor->choice.addressRange);
			if (error)
				return error;
			break;
		case IPAddressOrRange_PR_NOTHING:
			/* rfc3779#section-2.2.3.7 */
			return pr_err("Unknown IPAddressOrRange type: %d",
			    aor->present);
		}
	}

	return 0;
}

int
resources_add_ip(struct resources *resources, struct IPAddressFamily *obj)
{
	int family;

	family = get_addr_family(&obj->addressFamily);
	if (family == -1)
		return -EINVAL;

	switch (obj->ipAddressChoice.present) {
	case IPAddressChoice_PR_NOTHING:
		break;
	case IPAddressChoice_PR_inherit:
		return inherit_aors(resources, family);
	case IPAddressChoice_PR_addressesOrRanges:
		return add_aors(resources, family,
		    &obj->ipAddressChoice.choice.addressesOrRanges);
	}

	/* rfc3779#section-2.2.3.4 */
	return pr_err("Unknown ipAddressChoice type: %d",
	    obj->ipAddressChoice.present);
}

static int
inherit_asiors(struct resources *resources)
{
	struct resources *parent;

	parent = get_parent_resources();
	if (parent == NULL)
		return pr_err("Certificate inherits ASN resources, but parent does not define any resources.");

	if (resources->asns != NULL)
		return pr_err("Certificate inherits ASN resources while also defining others of its own.");
	if (parent->asns == NULL)
		return pr_err("Certificate inherits ASN resources from parent, but parent lacks ASN resources.");

	resources->asns = parent->asns;
	rasn_get(resources->asns);
	pr_debug("<Inherit ASN>");
	return 0;
}

static int
add_asn(struct resources *resources, ASId_t min, ASId_t max,
    struct resources *parent)
{
	int error;

	if (parent && !rasn_contains(parent->asns, min, max))
		return pr_err("Parent certificate doesn't own child's ASN resource.");

	if (resources->asns == NULL) {
		resources->asns = rasn_create();
		if (resources->asns == NULL)
			return pr_enomem();
	}

	error = rasn_add(resources->asns, min, max);
	if (error){
		pr_err("Error adding ASN range to certificate resources: %s",
		    sarray_err2str(error));
		return error;
	}

	if (min == max)
		pr_debug("ASN: %ld", min);
	else
		pr_debug("ASN: %ld-%ld", min, max);
	return 0;
}

static int
add_asior(struct resources *resources, struct ASIdOrRange *obj)
{
	struct resources *parent;

	parent = get_parent_resources();

	if ((parent != NULL) && (resources->asns == parent->asns))
		return pr_err("Certificate defines ASN resources while also inheriting his parent's.");

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

	return pr_err("Unknown ASIdOrRange type: %d", obj->present);
}

int
resources_add_asn(struct resources *resources, struct ASIdentifiers *ids)
{
	struct ASIdentifierChoice__asIdsOrRanges *iors;
	int i;
	int error;

	if (ids->asnum == NULL)
		return pr_err("ASN extension lacks 'asnum' element.");
	if (ids->rdi != NULL)
		return pr_err("ASN extension has 'rdi' element. (Prohibited by RFC6487)");

	switch (ids->asnum->present) {
	case ASIdentifierChoice_PR_inherit:
		return inherit_asiors(resources);
	case ASIdentifierChoice_PR_asIdsOrRanges:
		iors = &ids->asnum->choice.asIdsOrRanges;
		for (i = 0; i < iors->list.count; i++) {
			error = add_asior(resources, iors->list.array[i]);
			if (error)
				return error;
		}
		return 0;

	case ASIdentifierChoice_PR_NOTHING:
		break;
	}

	return pr_err("Unknown ASIdentifierChoice: %d", ids->asnum->present);
}

bool
resources_empty(struct resources *res)
{
	return rasn_empty(res->asns)
	    && res4_empty(res->ip4s)
	    && res6_empty(res->ip6s);
}

bool
resources_contains_asn(struct resources *res, ASId_t asn)
{
	return rasn_contains(res->asns, asn, asn);
}

bool
resources_contains_ipv4(struct resources *res, struct ipv4_prefix *prefix)
{
	return res4_contains_prefix(res->ip4s, prefix);
}

bool
resources_contains_ipv6(struct resources *res, struct ipv6_prefix *prefix)
{
	return res6_contains_prefix(res->ip6s, prefix);
}

