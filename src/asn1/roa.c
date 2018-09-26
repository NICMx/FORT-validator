#include "roa.h"

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include "oid.h"
#include "asn1/decode.h"
#include "asn1/signed_data.h"

static int
validate_eContentType(struct SignedData *sdata)
{
	struct oid_arcs arcs;
	bool equals;
	int error;

	error = oid2arcs(&sdata->encapContentInfo.eContentType, &arcs);
	if (error)
		return error;
	equals = ARCS_EQUAL_OIDS(&arcs, ROA_OID);
	free_arcs(&arcs);
	if (!equals) {
		warnx("SignedObject lacks the OID of a ROA.");
		return -EINVAL;
	}

	return 0;
}

static int
validate_content_type(struct SignedData *sdata)
{
	OBJECT_IDENTIFIER_t *ctype;
	struct oid_arcs arcs;
	bool equals;
	int error;

	error = get_content_type_attr(sdata, &ctype);
	if (error)
		return error;
	error = oid2arcs(ctype, &arcs);
	ASN_STRUCT_FREE(asn_DEF_OBJECT_IDENTIFIER, ctype);
	if (error)
		return error;
	equals = ARCS_EQUAL_OIDS(&arcs, ROA_OID);
	free_arcs(&arcs);
	if (!equals) {
		warnx("SignedObject's content type doesn't match its encapContentInfo's eContent.");
		return -EINVAL;
	}

	return 0;
}

static int
validate_roa(struct RouteOriginAttestation *roa)
{
	struct ROAIPAddressFamily *family;
	struct ROAIPAddress *addr;
	int b; /* block counter */
	int a; /* address counter */

	/* rfc6482#section-3.1 */
	if (roa->version != 0) {
		warnx("ROA's version (%ld) is not zero.", roa->version);
		return -EINVAL;
	}

	/* rfc6482#section-3.2 */
	if (roa->ipAddrBlocks.list.array == NULL)
		return -EINVAL;

	for (b = 0; b < roa->ipAddrBlocks.list.count; b++) {
		family = roa->ipAddrBlocks.list.array[0];
		if (family == NULL)
			return -EINVAL;

		if (family->addressFamily.size != 2)
			return -EINVAL;
		if (family->addressFamily.buf[0] != 0)
			return -EINVAL;
		if (family->addressFamily.buf[1] != 1
		    && family->addressFamily.buf[1] != 2)
			return -EINVAL;

		if (family->addresses.list.array == NULL)
			return -EINVAL;
		for (a = 0; a < family->addresses.list.count; a++) {
			addr = family->addresses.list.array[a];
			/*
			 * TODO I don't understand where the prefix length is.
			 * The bit string's size is measured in bytes...
			 */
			printf("%ld\n", addr->maxLength
			    ? (*addr->maxLength)
			    : -1);
		}
	}

	return 0;
}

int
roa_decode(struct SignedData *sdata, struct RouteOriginAttestation **result)
{
	struct RouteOriginAttestation *roa;
	int error;

	/* rfc6482#section-2: eContentType */
	error = validate_eContentType(sdata);
	if (error)
		return error;

	/* rfc6482#section-2: content-type */
	error = validate_content_type(sdata);
	if (error)
		return error;

	error = asn1_decode_octet_string(sdata->encapContentInfo.eContent,
	    &asn_DEF_RouteOriginAttestation, (void **) &roa);
	if (error)
		return -EINVAL;

	error = validate_roa(roa);
	if (error) {
		ASN_STRUCT_FREE(asn_DEF_RouteOriginAttestation, roa);
		return error;
	}

	*result = roa;
	return 0;
}

void roa_free(struct RouteOriginAttestation *roa)
{
	ASN_STRUCT_FREE(asn_DEF_RouteOriginAttestation, roa);
}
