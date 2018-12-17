#include "object/roa.h"

#include <errno.h>
#include <arpa/inet.h>
#include <libcmscodec/RouteOriginAttestation.h>

#include "log.h"
#include "thread_var.h"
#include "asn1/oid.h"
#include "object/signed_object.h"

static int
print_addr4(struct resources *parent, long asn, struct ROAIPAddress *roa_addr)
{
	struct ipv4_prefix prefix;
	char str[INET_ADDRSTRLEN];
	const char *str2;
	int error;

	error = prefix4_decode(&roa_addr->address, &prefix);
	if (error)
		return error;

	str2 = inet_ntop(AF_INET, &prefix.addr, str, sizeof(str));
	if (str2 == NULL) {
		pr_err("inet_ntop() returned NULL.");
		return -EINVAL;
	}

	if (roa_addr->maxLength != NULL)
		if (prefix.len > *roa_addr->maxLength)
			goto unallowed;
	if (!resources_contains_ipv4(parent, &prefix))
		goto unallowed;

	printf("%ld,%s/%u\n", asn, str2, prefix.len);
	return 0;

unallowed:
	pr_err("ROA is not allowed to advertise %s/%u.", str2, prefix.len);
	return -EINVAL;
}

static int
print_addr6(struct resources *parent, long asn, struct ROAIPAddress *roa_addr)
{
	struct ipv6_prefix prefix;
	char str[INET6_ADDRSTRLEN];
	const char *str2;
	int error;

	error = prefix6_decode(&roa_addr->address, &prefix);
	if (error)
		return error;

	str2 = inet_ntop(AF_INET6, &prefix.addr, str, sizeof(str));
	if (str2 == NULL) {
		pr_err("inet_ntop() returned NULL.");
		return -EINVAL;
	}

	if (roa_addr->maxLength != NULL)
		if (prefix.len > *roa_addr->maxLength)
			goto unallowed;
	if (!resources_contains_ipv6(parent, &prefix))
		goto unallowed;

	printf("%ld,%s/%u\n", asn, str2, prefix.len);
	return 0;

unallowed:
	pr_err("ROA is not allowed to advertise %s/%u.", str2, prefix.len);
	return -EINVAL;
}

static int
print_addr(struct resources *parent, long asn, uint8_t family,
    struct ROAIPAddress *roa_addr)
{
	switch (family) {
	case 1: /* IPv4 */
		return print_addr4(parent, asn, roa_addr);
	case 2: /* IPv6 */
		return print_addr6(parent, asn, roa_addr);
	}

	pr_err("Unknown family value: %u", family);
	return -EINVAL;
}

static int
__handle_roa(struct RouteOriginAttestation *roa, struct resources *parent)
{
	struct ROAIPAddressFamily *block;
	int b;
	int a;
	int error;

	/* rfc6482#section-3.1 */
	if (roa->version != 0) {
		pr_err("ROA's version (%ld) is nonzero.", roa->version);
		return -EINVAL;
	}

	/* rfc6482#section-3.2 (more or less.) */
	if (!resources_contains_asn(parent, roa->asID)) {
		pr_err("ROA is not allowed to attest for AS %d",
		    roa->asID);
		return -EINVAL;
	}

	/* rfc6482#section-3.3 */

	if (roa->ipAddrBlocks.list.array == NULL) {
		pr_err("Programming error: ipAddrBlocks array is NULL.");
		return -EINVAL;
	}

	for (b = 0; b < roa->ipAddrBlocks.list.count; b++) {
		block = roa->ipAddrBlocks.list.array[0];
		if (block == NULL) {
			pr_err("Address block array element is NULL.");
			return -EINVAL;
		}

		if (block->addressFamily.size != 2)
			goto family_error;
		if (block->addressFamily.buf[0] != 0)
			goto family_error;
		if (block->addressFamily.buf[1] != 1
		    && block->addressFamily.buf[1] != 2)
			goto family_error;

		if (block->addresses.list.array == NULL) {
			pr_err("ROA's address list array is NULL.");
			return -EINVAL;
		}
		for (a = 0; a < block->addresses.list.count; a++) {
			error = print_addr(parent, roa->asID,
			    block->addressFamily.buf[1],
			    block->addresses.list.array[a]);
			if (error)
				return error;
		}
	}

	return 0;

family_error:
	pr_err("ROA's IP family is not v4 or v6.");
	return -EINVAL;
}

int handle_roa(char const *file, STACK_OF(X509_CRL) *crls)
{
	static OID oid = OID_ROA;
	struct oid_arcs arcs = OID2ARCS(oid);
	struct RouteOriginAttestation *roa;
	/* Resources contained in the ROA certificate, not in the ROA itself. */
	struct resources *cert_resources;
	int error;

	pr_debug_add("ROA %s {", file);
	fnstack_push(file);

	cert_resources = resources_create();
	if (cert_resources == NULL) {
		pr_err("Out of memory");
		error = -ENOMEM;
		goto end1;
	}

	error = signed_object_decode(file, &asn_DEF_RouteOriginAttestation,
	    &arcs, (void **) &roa, crls, cert_resources);
	if (error)
		goto end2;
	error = __handle_roa(roa, cert_resources);
	ASN_STRUCT_FREE(asn_DEF_RouteOriginAttestation, roa);

end2:
	resources_destroy(cert_resources);
end1:
	pr_debug_rm("}");
	fnstack_pop();
	return error;
}
