#include "object/roa.h"

#include <errno.h>
#include <arpa/inet.h>
#include <libcmscodec/RouteOriginAttestation.h>

#include "log.h"
#include "thread_var.h"
#include "asn1/decode.h"
#include "asn1/oid.h"
#include "object/signed_object.h"

static int
roa_decode(OCTET_STRING_t *string, void *arg)
{
	return asn1_decode_octet_string(string, &asn_DEF_RouteOriginAttestation,
	    arg);
}

static int
print_addr4(struct resources *parent, unsigned long asn,
    struct ROAIPAddress *roa_addr)
{
	struct ipv4_prefix prefix;
	unsigned long max_length;
	char str[INET_ADDRSTRLEN];
	const char *str2;
	int error;

	error = prefix4_decode(&roa_addr->address, &prefix);
	if (error)
		return error;

	if (roa_addr->maxLength != NULL) {
		error = asn_INTEGER2ulong(roa_addr->maxLength, &max_length);
		if (error) {
			if (errno)
				pr_errno(errno, "Error casting ROA's IPv4 maxLength");
			return pr_err("The ROA's IPv4 maxLength isn't a valid unsigned long");
		}

		if (max_length > 32) {
			return pr_err("maxLength (%lu) is out of bounds (0-32).",
			    max_length);
		}

		if (prefix.len > max_length) {
			return pr_err("Prefix length (%u) > maxLength (%lu)",
			    prefix.len, max_length);
		}
	}

	str2 = inet_ntop(AF_INET, &prefix.addr, str, sizeof(str));
	if (str2 == NULL)
		return pr_err("inet_ntop() returned NULL.");

	if (!resources_contains_ipv4(parent, &prefix)) {
		return pr_err("ROA is not allowed to advertise %s/%u.", str2,
		    prefix.len);
	}

	printf("AS%lu,%s/%u", asn, str2, prefix.len);
	if (roa_addr->maxLength != NULL)
		printf(",%lu", max_length);
	else
		printf(",%u", prefix.len);
	printf("\n");

	return 0;
}

static int
print_addr6(struct resources *parent, unsigned long asn,
    struct ROAIPAddress *roa_addr)
{
	struct ipv6_prefix prefix;
	unsigned long max_length;
	char str[INET6_ADDRSTRLEN];
	const char *str2;
	int error;

	error = prefix6_decode(&roa_addr->address, &prefix);
	if (error)
		return error;

	if (roa_addr->maxLength != NULL) {
		error = asn_INTEGER2ulong(roa_addr->maxLength, &max_length);
		if (error) {
			if (errno)
				pr_errno(errno, "Error casting ROA's IPv6 maxLength");
			return pr_err("The ROA's IPv6 maxLength isn't a valid unsigned long");
		}

		if (max_length > 128) {
			return pr_err("maxLength (%lu) is out of bounds (0-128).",
			    max_length);
		}

		if (prefix.len > max_length) {
			return pr_err("Prefix length (%u) > maxLength (%lu)",
			    prefix.len, max_length);
		}
	}

	str2 = inet_ntop(AF_INET6, &prefix.addr, str, sizeof(str));
	if (str2 == NULL)
		return pr_err("inet_ntop() returned NULL.");

	if (!resources_contains_ipv6(parent, &prefix)) {
		return pr_err("ROA is not allowed to advertise %s/%u.", str2,
		    prefix.len);
	}

	printf("AS%lu,%s/%u", asn, str2, prefix.len);
	if (roa_addr->maxLength != NULL)
		printf(",%lu", max_length);
	else
		printf(",%u", prefix.len);
	printf("\n");

	return 0;
}

static int
print_addr(struct resources *parent, ASID_t *as_id, uint8_t family,
    struct ROAIPAddress *roa_addr)
{
	unsigned long asn;

	if (asn_INTEGER2ulong(as_id, &asn) != 0) {
		if (errno)
			pr_errno(errno, "Error casting ROA's AS ID value");
		return pr_err("ROA's AS ID couldn't be parsed as unsigned long");
	}

	switch (family) {
	case 1: /* IPv4 */
		return print_addr4(parent, asn, roa_addr);
	case 2: /* IPv6 */
		return print_addr6(parent, asn, roa_addr);
	}

	return pr_err("Unknown family value: %u", family);
}

static int
__handle_roa(struct RouteOriginAttestation *roa, struct resources *parent)
{
	struct ROAIPAddressFamily *block;
	unsigned long version;
	int b;
	int a;
	int error;

	if (roa->version != NULL) {
		error = asn_INTEGER2ulong(roa->version, &version);
		if (error) {
			if (errno)
				pr_errno(errno, "Error casting ROA's version");
			return pr_err("The ROA's version isn't a valid long");
		}
		/* rfc6482#section-3.1 */
		if (version != 0)
			return pr_err("ROA's version (%lu) is nonzero.", version);
	}

	/* rfc6482#section-3.3 */

	if (roa->ipAddrBlocks.list.array == NULL)
		return pr_crit("ipAddrBlocks array is NULL.");

	for (b = 0; b < roa->ipAddrBlocks.list.count; b++) {
		block = roa->ipAddrBlocks.list.array[b];
		if (block == NULL)
			return pr_err("Address block array element is NULL.");

		if (block->addressFamily.size != 2)
			goto family_error;
		if (block->addressFamily.buf[0] != 0)
			goto family_error;
		if (block->addressFamily.buf[1] != 1
		    && block->addressFamily.buf[1] != 2)
			goto family_error;

		if (block->addresses.list.array == NULL)
			return pr_err("ROA's address list array is NULL.");
		for (a = 0; a < block->addresses.list.count; a++) {
			error = print_addr(parent, &roa->asID,
			    block->addressFamily.buf[1],
			    block->addresses.list.array[a]);
			if (error)
				return error;
		}
	}

	return 0;

family_error:
	return pr_err("ROA's IP family is not v4 or v6.");
}

int
handle_roa(struct rpki_uri const *uri, struct rpp *pp,
    STACK_OF(X509_CRL) *crls)
{
	static OID oid = OID_ROA;
	struct oid_arcs arcs = OID2ARCS("roa", oid);
	struct signed_object_args sobj_args;
	struct RouteOriginAttestation *roa;
	int error;

	pr_debug_add("ROA %s {", uri->global);
	fnstack_push(uri->global);

	error = signed_object_args_init(&sobj_args, uri, crls);
	if (error)
		goto end1;

	error = signed_object_decode(&sobj_args, &arcs, roa_decode, &roa);
	if (error)
		goto end2;

	error = __handle_roa(roa, sobj_args.res);
	if (error)
		goto end3;

	error = refs_validate_ee(&sobj_args.refs, pp, sobj_args.uri);

end3:
	ASN_STRUCT_FREE(asn_DEF_RouteOriginAttestation, roa);
end2:
	signed_object_args_cleanup(&sobj_args);
end1:
	pr_debug_rm("}");
	fnstack_pop();
	return error;
}
