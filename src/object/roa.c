#include "object/roa.h"

#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "config.h"
#include "log.h"
#include "thread_var.h"
#include "asn1/decode.h"
#include "asn1/oid.h"
#include "asn1/asn1c/RouteOriginAttestation.h"
#include "object/signed_object.h"

static int
roa_decode(OCTET_STRING_t *string, void *arg)
{
	return asn1_decode_octet_string(string, &asn_DEF_RouteOriginAttestation,
	    arg, true);
}

static int
____handle_roa_v4(struct resources *parent, unsigned long asn,
    struct ROAIPAddress *roa_addr)
{
	struct ipv4_prefix prefix;
	unsigned long max_length;
	int error;

	error = prefix4_decode(&roa_addr->address, &prefix);
	if (error)
		return error;

	pr_debug_add("ROAIPAddress {");
	pr_debug("address: %s/%u", v4addr2str(&prefix.addr), prefix.len);

	if (roa_addr->maxLength != NULL) {
		error = asn_INTEGER2ulong(roa_addr->maxLength, &max_length);
		if (error) {
			if (errno)
				pr_errno(errno, "Error casting ROA's IPv4 maxLength");
			error = pr_err("The ROA's IPv4 maxLength isn't a valid unsigned long");
			goto end_error;
		}
		pr_debug("maxLength: %lu", max_length);

		if (max_length > 32) {
			error = pr_err("maxLength (%lu) is out of bounds (0-32).",
			    max_length);
			goto end_error;
		}

		if (prefix.len > max_length) {
			error = pr_err("Prefix length (%u) > maxLength (%lu)",
			    prefix.len, max_length);
			goto end_error;
		}

	} else {
		max_length = prefix.len;
	}

	if (!resources_contains_ipv4(parent, &prefix)) {
		error = pr_err("ROA is not allowed to advertise %s/%u.",
		    v4addr2str(&prefix.addr), prefix.len);
		goto end_error;
	}

	if (!resources_contains_asn(parent, asn)) {
		error = pr_err("ROA is not allowed to advertise ASN %lu.",
		    asn);
		goto end_error;
	}

	pr_debug_rm("}");
	return vhandler_handle_roa_v4(asn, &prefix, max_length);
end_error:
	pr_debug_rm("}");
	return error;
}

static int
____handle_roa_v6(struct resources *parent, unsigned long asn,
    struct ROAIPAddress *roa_addr)
{
	struct ipv6_prefix prefix;
	unsigned long max_length;
	int error;

	error = prefix6_decode(&roa_addr->address, &prefix);
	if (error)
		return error;

	pr_debug_add("ROAIPAddress {");
	pr_debug("address: %s/%u", v6addr2str(&prefix.addr), prefix.len);

	if (roa_addr->maxLength != NULL) {
		error = asn_INTEGER2ulong(roa_addr->maxLength, &max_length);
		if (error) {
			if (errno)
				pr_errno(errno, "Error casting ROA's IPv6 maxLength");
			error = pr_err("The ROA's IPv6 maxLength isn't a valid unsigned long");
			goto end_error;
		}
		pr_debug("maxLength: %lu", max_length);

		if (max_length > 128) {
			error = pr_err("maxLength (%lu) is out of bounds (0-128).",
			    max_length);
			goto end_error;
		}

		if (prefix.len > max_length) {
			error = pr_err("Prefix length (%u) > maxLength (%lu)",
			    prefix.len, max_length);
			goto end_error;
		}

	} else {
		max_length = prefix.len;
	}

	if (!resources_contains_ipv6(parent, &prefix)) {
		error = pr_err("ROA is not allowed to advertise %s/%u.",
		    v6addr2str(&prefix.addr), prefix.len);
		goto end_error;
	}

	if (!resources_contains_asn(parent, asn)) {
		error = pr_err("ROA is not allowed to advertise ASN %lu.",
		    asn);
		goto end_error;
	}

	pr_debug_rm("}");
	return vhandler_handle_roa_v6(asn, &prefix, max_length);
end_error:
	pr_debug_rm("}");
	return error;
}

static int
____handle_roa(struct resources *parent, unsigned long asn, uint8_t family,
    struct ROAIPAddress *roa_addr)
{
	switch (family) {
	case 1: /* IPv4 */
		return ____handle_roa_v4(parent, asn, roa_addr);
	case 2: /* IPv6 */
		return ____handle_roa_v6(parent, asn, roa_addr);
	}

	return pr_err("Unknown family value: %u", family);
}

static int
__handle_roa(struct RouteOriginAttestation *roa, struct resources *parent)
{
	struct ROAIPAddressFamily *block;
	unsigned long version;
	unsigned long asn;
	int b;
	int a;
	int error;


	pr_debug_add("eContent {");
	if (roa->version != NULL) {
		error = asn_INTEGER2ulong(roa->version, &version);
		if (error) {
			if (errno)
				pr_errno(errno, "Error casting ROA's version");
			error = pr_err("The ROA's version isn't a valid long");
			goto end_error;
		}
		/* rfc6482#section-3.1 */
		if (version != 0) {
			error = pr_err("ROA's version (%lu) is nonzero.",
			    version);
			goto end_error;
		}
	}

	/* rfc6482#section-3.2 */
	if (asn_INTEGER2ulong(&roa->asID, &asn) != 0) {
		if (errno)
			pr_errno(errno, "Error casting ROA's AS ID value");
		error = pr_err("ROA's AS ID couldn't be parsed as unsigned long");
		goto end_error;
	}

	if (asn > UINT32_MAX) {
		error = pr_err("AS value (%lu) is out of range.", asn);
		goto end_error;
	}
	pr_debug("asID: %lu", asn);

	/* rfc6482#section-3.3 */

	if (roa->ipAddrBlocks.list.array == NULL)
		pr_crit("ipAddrBlocks array is NULL.");

	pr_debug_add("ipAddrBlocks {");
	for (b = 0; b < roa->ipAddrBlocks.list.count; b++) {
		block = roa->ipAddrBlocks.list.array[b];
		if (block == NULL) {
			error = pr_err("Address block array element is NULL.");
			goto ip_error;
		}

		if (block->addressFamily.size != 2)
			goto family_error;
		if (block->addressFamily.buf[0] != 0)
			goto family_error;
		if (block->addressFamily.buf[1] != 1
		    && block->addressFamily.buf[1] != 2)
			goto family_error;
		pr_debug_add("%s {",
		    block->addressFamily.buf[1] == 1 ? "v4" : "v6");

		if (block->addresses.list.array == NULL) {
			error = pr_err("ROA's address list array is NULL.");
			pr_debug_rm("}");
			goto ip_error;
		}

		for (a = 0; a < block->addresses.list.count; a++) {
			error = ____handle_roa(parent, asn,
			    block->addressFamily.buf[1],
			    block->addresses.list.array[a]);
			if (error) {
				pr_debug_rm("}");
				goto ip_error;
			}
		}
		pr_debug_rm("}");
	}

	/* Error 0 it's ok */
	error = 0;
	goto ip_error;

family_error:
	error = pr_err("ROA's IP family is not v4 or v6.");
ip_error:
	pr_debug_rm("}");
end_error:
	pr_debug_rm("}");
	return error;
}

int
roa_traverse(struct rpki_uri *uri, struct rpp *pp)
{
	static OID oid = OID_ROA;
	struct oid_arcs arcs = OID2ARCS("roa", oid);
	struct signed_object_args sobj_args;
	struct RouteOriginAttestation *roa;
	STACK_OF(X509_CRL) *crl;
	int error;

	pr_debug_add("ROA '%s' {", uri_get_printable(uri));
	fnstack_push_uri(uri);

	error = rpp_crl(pp, &crl);
	if (error)
		goto revert_fnstack;

	error = signed_object_args_init(&sobj_args, uri, crl, false);
	if (error)
		goto revert_fnstack;

	error = signed_object_decode(&sobj_args, &arcs, roa_decode, &roa);
	if (error)
		goto revert_sobj;

	error = refs_validate_ee(&sobj_args.refs, pp, sobj_args.uri);
	if (error)
		goto revert_roa;

	error = __handle_roa(roa, sobj_args.res);

revert_roa:
	ASN_STRUCT_FREE(asn_DEF_RouteOriginAttestation, roa);
revert_sobj:
	signed_object_args_cleanup(&sobj_args);
revert_fnstack:
	fnstack_pop();
	pr_debug_rm("}");
	return error;
}
