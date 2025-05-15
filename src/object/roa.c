#include "object/roa.h"

#include "asn1/asn1c/RouteOriginAttestation.h"
#include "asn1/decode.h"
#include "log.h"
#include "object/signed_object.h"
#include "thread_var.h"
#include "validation_handler.h"

static int
decode_roa(struct signed_object *so, struct RouteOriginAttestation **result)
{
	return asn1_decode_octet_string(
		so->sdata->encapContentInfo.eContent,
		&asn_DEF_RouteOriginAttestation,
		(void **) result,
		true
	);
}

static int
____handle_roa_v4(struct resources *parent, unsigned long asn,
    struct ROAIPAddress *roa_addr)
{
	struct ipv4_prefix pfx;
	unsigned long maxlen;
	char buf[INET_ADDRSTRLEN];
	int error;

	error = prefix4_decode(&roa_addr->address, &pfx);
	if (error)
		return error;

	pr_clutter("address: %s/%u", addr2str4(&pfx.addr, buf), pfx.len);

	if (roa_addr->maxLength != NULL) {
		error = asn_INTEGER2ulong(roa_addr->maxLength, &maxlen);
		if (error) {
			if (errno) {
				pr_val_err("Error casting ROA's IPv4 maxLength: %s",
				    strerror(errno));
			}
			return pr_val_err("The ROA's IPv4 maxLength isn't a valid unsigned long");
		}
		pr_clutter("maxLength: %lu", maxlen);

		if (maxlen > 32) {
			return pr_val_err("maxLength (%lu) is out of bounds (0-32).",
			    maxlen);
		}

		if (pfx.len > maxlen) {
			return pr_val_err("Prefix length (%u) > maxLength (%lu)",
			    pfx.len, maxlen);
		}

	} else {
		maxlen = pfx.len;
	}

	if (!resources_contains_ipv4(parent, &pfx)) {
		return pr_val_err("ROA is not allowed to advertise %s/%u.",
		    addr2str4(&pfx.addr, buf), pfx.len);
	}

	return vhandle_roa_v4(asn, &pfx, maxlen);
}

static int
____handle_roa_v6(struct resources *parent, unsigned long asn,
    struct ROAIPAddress *roa_addr)
{
	struct ipv6_prefix pfx;
	unsigned long maxlen;
	char buf[INET6_ADDRSTRLEN];
	int error;

	error = prefix6_decode(&roa_addr->address, &pfx);
	if (error)
		return error;

	pr_clutter("address: %s/%u", addr2str6(&pfx.addr, buf), pfx.len);

	if (roa_addr->maxLength != NULL) {
		error = asn_INTEGER2ulong(roa_addr->maxLength, &maxlen);
		if (error) {
			if (errno) {
				pr_val_err("Error casting ROA's IPv6 maxLength: %s",
				    strerror(errno));
			}
			return pr_val_err("The ROA's IPv6 maxLength isn't a valid unsigned long");
		}
		pr_clutter("maxLength: %lu", maxlen);

		if (maxlen > 128) {
			return pr_val_err("maxLength (%lu) is out of bounds (0-128).",
			    maxlen);
		}

		if (pfx.len > maxlen) {
			return pr_val_err("Prefix length (%u) > maxLength (%lu)",
			    pfx.len, maxlen);
		}

	} else {
		maxlen = pfx.len;
	}

	if (!resources_contains_ipv6(parent, &pfx)) {
		return pr_val_err("ROA is not allowed to advertise %s/%u.",
		    addr2str6(&pfx.addr, buf), pfx.len);
	}

	return vhandle_roa_v6(asn, &pfx, maxlen);
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

	if (roa->version != NULL) {
		error = asn_INTEGER2ulong(roa->version, &version);
		if (error) {
			if (errno) {
				pr_val_err("Error casting ROA's version: %s",
				    strerror(errno));
			}
			return pr_val_err("The ROA's version isn't a valid long");
		}
		/* rfc6482#section-3.1 */
		if (version != 0) {
			return pr_val_err("ROA's version (%lu) is nonzero.",
			    version);
		}
	}

	/* rfc6482#section-3.2 */
	if (asn_INTEGER2ulong(&roa->asId, &asn) != 0) {
		if (errno) {
			pr_val_err("Error casting ROA's AS ID value: %s",
			    strerror(errno));
		}
		return pr_val_err("ROA's AS ID couldn't be parsed as unsigned long");
	}

	if (asn > UINT32_MAX)
		return pr_val_err("AS value (%lu) is out of range.", asn);

	/* rfc6482#section-3.3 */

	if (roa->ipAddrBlocks.list.array == NULL)
		return pr_val_err("ipAddrBlocks array is NULL.");

	for (b = 0; b < roa->ipAddrBlocks.list.count; b++) {
		block = roa->ipAddrBlocks.list.array[b];
		if (block == NULL)
			return pr_val_err("Address block array element is NULL.");

		if (block->addressFamily.size != 2)
			goto family_error;
		if (block->addressFamily.buf[0] != 0)
			goto family_error;
		if (block->addressFamily.buf[1] != 1 &&
		    block->addressFamily.buf[1] != 2)
			goto family_error;

		if (block->addresses.list.array == NULL)
			return pr_val_err("ROA's address list array is NULL.");

		for (a = 0; a < block->addresses.list.count; a++) {
			error = ____handle_roa(parent, asn,
			    block->addressFamily.buf[1],
			    block->addresses.list.array[a]);
			if (error)
				return error;
		}
	}

	return 0;

family_error:
	return pr_val_err("ROA's IP family is not v4 or v6.");
}

int
roa_traverse(struct cache_mapping *map, struct rpki_certificate *parent)
{
	static OID oid = OID_ROA;
	struct oid_arcs arcs = OID2ARCS("roa", oid);
	struct signed_object so;
	struct rpki_certificate ee;
	struct RouteOriginAttestation *roa;
	int error;

	/* Prepare */
	fnstack_push_map(map);

	/* Decode */
	error = signed_object_decode(&so, map);
	if (error)
		goto end1;
	error = decode_roa(&so, &roa);
	if (error)
		goto end2;

	/* Prepare validation arguments */
	cer_init_ee(&ee, parent, false);

	/* Validate and handle everything */
	error = signed_object_validate(&so, &ee, &arcs);
	if (error)
		goto end4;
	error = __handle_roa(roa, ee.resources);

end4:	cer_cleanup(&ee);
	ASN_STRUCT_FREE(asn_DEF_RouteOriginAttestation, roa);
end2:	signed_object_cleanup(&so);
end1:	fnstack_pop();
	return error;
}
