#include "object/roa.h"

#include "asn1/asn1c/RouteOriginAttestation.h"
#include "asn1/decode.h"
#include "log.h"
#include "object/signed_object.h"
#include "thread_var.h"

static int
decode_roa(struct signed_object *sobj, struct RouteOriginAttestation **result)
{
	return asn1_decode_octet_string(
		sobj->sdata->encapContentInfo.eContent,
		&asn_DEF_RouteOriginAttestation,
		(void **) result,
		true
	);
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

	pr_val_debug("ROAIPAddress {");
	pr_val_debug("address: %s/%u", v4addr2str(&prefix.addr), prefix.len);

	if (roa_addr->maxLength != NULL) {
		error = asn_INTEGER2ulong(roa_addr->maxLength, &max_length);
		if (error) {
			if (errno) {
				pr_val_err("Error casting ROA's IPv4 maxLength: %s",
				    strerror(errno));
			}
			error = pr_val_err("The ROA's IPv4 maxLength isn't a valid unsigned long");
			goto end_error;
		}
		pr_val_debug("maxLength: %lu", max_length);

		if (max_length > 32) {
			error = pr_val_err("maxLength (%lu) is out of bounds (0-32).",
			    max_length);
			goto end_error;
		}

		if (prefix.len > max_length) {
			error = pr_val_err("Prefix length (%u) > maxLength (%lu)",
			    prefix.len, max_length);
			goto end_error;
		}

	} else {
		max_length = prefix.len;
	}

	if (!resources_contains_ipv4(parent, &prefix)) {
		error = pr_val_err("ROA is not allowed to advertise %s/%u.",
		    v4addr2str(&prefix.addr), prefix.len);
		goto end_error;
	}

	pr_val_debug("}");
	return vhandler_handle_roa_v4(asn, &prefix, max_length);
end_error:
	pr_val_debug("}");
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

	pr_val_debug("ROAIPAddress {");
	pr_val_debug("address: %s/%u", v6addr2str(&prefix.addr), prefix.len);

	if (roa_addr->maxLength != NULL) {
		error = asn_INTEGER2ulong(roa_addr->maxLength, &max_length);
		if (error) {
			if (errno) {
				pr_val_err("Error casting ROA's IPv6 maxLength: %s",
				    strerror(errno));
			}
			error = pr_val_err("The ROA's IPv6 maxLength isn't a valid unsigned long");
			goto end_error;
		}
		pr_val_debug("maxLength: %lu", max_length);

		if (max_length > 128) {
			error = pr_val_err("maxLength (%lu) is out of bounds (0-128).",
			    max_length);
			goto end_error;
		}

		if (prefix.len > max_length) {
			error = pr_val_err("Prefix length (%u) > maxLength (%lu)",
			    prefix.len, max_length);
			goto end_error;
		}

	} else {
		max_length = prefix.len;
	}

	if (!resources_contains_ipv6(parent, &prefix)) {
		error = pr_val_err("ROA is not allowed to advertise %s/%u.",
		    v6addr2str(&prefix.addr), prefix.len);
		goto end_error;
	}

	pr_val_debug("}");
	return vhandler_handle_roa_v6(asn, &prefix, max_length);
end_error:
	pr_val_debug("}");
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

	return pr_val_err("Unknown family value: %u", family);
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

	pr_val_debug("eContent {");
	if (roa->version != NULL) {
		error = asn_INTEGER2ulong(roa->version, &version);
		if (error) {
			if (errno) {
				pr_val_err("Error casting ROA's version: %s",
				    strerror(errno));
			}
			error = pr_val_err("The ROA's version isn't a valid long");
			goto end_error;
		}
		/* rfc6482#section-3.1 */
		if (version != 0) {
			error = pr_val_err("ROA's version (%lu) is nonzero.",
			    version);
			goto end_error;
		}
	}

	/* rfc6482#section-3.2 */
	if (asn_INTEGER2ulong(&roa->asId, &asn) != 0) {
		if (errno) {
			pr_val_err("Error casting ROA's AS ID value: %s",
			    strerror(errno));
		}
		error = pr_val_err("ROA's AS ID couldn't be parsed as unsigned long");
		goto end_error;
	}

	if (asn > UINT32_MAX) {
		error = pr_val_err("AS value (%lu) is out of range.", asn);
		goto end_error;
	}
	pr_val_debug("asId: %lu", asn);

	/* rfc6482#section-3.3 */

	if (roa->ipAddrBlocks.list.array == NULL) {
		error = pr_val_err("ipAddrBlocks array is NULL.");
		goto end_error;
	}

	pr_val_debug("ipAddrBlocks {");
	for (b = 0; b < roa->ipAddrBlocks.list.count; b++) {
		block = roa->ipAddrBlocks.list.array[b];
		if (block == NULL) {
			error = pr_val_err("Address block array element is NULL.");
			goto ip_error;
		}

		if (block->addressFamily.size != 2)
			goto family_error;
		if (block->addressFamily.buf[0] != 0)
			goto family_error;
		if (block->addressFamily.buf[1] != 1
		    && block->addressFamily.buf[1] != 2)
			goto family_error;
		pr_val_debug("%s {",
		    block->addressFamily.buf[1] == 1 ? "v4" : "v6");

		if (block->addresses.list.array == NULL) {
			error = pr_val_err("ROA's address list array is NULL.");
			pr_val_debug("}");
			goto ip_error;
		}

		for (a = 0; a < block->addresses.list.count; a++) {
			error = ____handle_roa(parent, asn,
			    block->addressFamily.buf[1],
			    block->addresses.list.array[a]);
			if (error) {
				pr_val_debug("}");
				goto ip_error;
			}
		}
		pr_val_debug("}");
	}

	/* Error 0 it's ok */
	error = 0;
	goto ip_error;

family_error:
	error = pr_val_err("ROA's IP family is not v4 or v6.");
ip_error:
	pr_val_debug("}");
end_error:
	pr_val_debug("}");
	return error;
}

int
roa_traverse(struct rpki_uri *uri, struct rpp *pp)
{
	static OID oid = OID_ROA;
	struct oid_arcs arcs = OID2ARCS("roa", oid);
	struct signed_object sobj;
	struct ee_cert ee;
	struct RouteOriginAttestation *roa;
	STACK_OF(X509_CRL) *crl;
	int error;

	/* Prepare */
	pr_val_debug("ROA '%s' {", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	/* Decode */
	error = signed_object_decode(&sobj, uri);
	if (error)
		goto revert_log;
	error = decode_roa(&sobj, &roa);
	if (error)
		goto revert_sobj;

	/* Prepare validation arguments */
	error = rpp_crl(pp, &crl);
	if (error)
		goto revert_roa;
	eecert_init(&ee, crl, false);

	/* Validate and handle everything */
	error = signed_object_validate(&sobj, &arcs, &ee);
	if (error)
		goto revert_args;
	error = __handle_roa(roa, ee.res);
	if (error)
		goto revert_args;
	error = refs_validate_ee(&ee.refs, pp, uri);

revert_args:
	eecert_cleanup(&ee);
revert_roa:
	ASN_STRUCT_FREE(asn_DEF_RouteOriginAttestation, roa);
revert_sobj:
	signed_object_cleanup(&sobj);
revert_log:
	fnstack_pop();
	pr_val_debug("}");
	return error;
}
