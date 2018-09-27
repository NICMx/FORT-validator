#include "asn1/manifest.h"

#include <err.h>
#include <errno.h>
#include "asn1/decode.h"
#include "asn1/oid.h"
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
	equals = ARCS_EQUAL_OIDS(&arcs, MANIFEST_OID);
	free_arcs(&arcs);
	if (!equals) {
		warnx("SignedObject lacks the OID of a Manifest.");
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
	equals = ARCS_EQUAL_OIDS(&arcs, MANIFEST_OID);
	free_arcs(&arcs);
	if (!equals) {
		warnx("SignedObject's content type doesn't match its encapContentInfo's eContent.");
		return -EINVAL;
	}

	return 0;
}

static int
validate_dates(GeneralizedTime_t *this, GeneralizedTime_t *next)
{
	const struct asn_TYPE_descriptor_s *def = &asn_DEF_GeneralizedTime;
	return (GeneralizedTime_compare(def, this, next) < 0) ? 0 : -EINVAL;
}

static int
is_hash_algorithm(OBJECT_IDENTIFIER_t *aid, bool *result)
{
	struct oid_arcs arcs;
	int error;

	error = oid2arcs(aid, &arcs);
	if (error)
		return error;

	*result = ARCS_EQUAL_OIDS(&arcs, OID_SHA256);

	free_arcs(&arcs);
	return 0;
}

int
validate_manifest(struct Manifest *manifest)
{
	int error;
	bool is_hash;

	/* rfc6486#section-4.2.1 */

	/*
	 * TODO
	 *
	 * If a "one-time-use" EE certificate is employed to verify a manifest,
	 * the EE certificate MUST have a validity period that coincides with
	 * the interval from thisUpdate to nextUpdate, to prevent needless
	 * growth of the CA's CRL.
	 *
	 * If a "sequential-use" EE certificate is employed to verify a
	 * manifest, the EE certificate's validity period needs to be no shorter
	 * than the nextUpdate time of the current manifest.
	 */

	/* rfc6486#section-4.4.2 */
	if (manifest->version != 0)
		return -EINVAL;

	/*
	 * TODO "Manifest verifiers MUST be able to handle number values up to
	 * 20 octets."
	 *
	 * What the fuck?
	 */
	/* manifest->manifestNumber; */

	/*
	 * TODO
	 *
	 * "CRL issuers conforming to this profile MUST encode thisUpdate as
	 * UTCTime for dates through the year 2049.  CRL issuers conforming to
	 * this profile MUST encode thisUpdate as GeneralizedTime for dates in
	 * the year 2050 or later. Conforming applications MUST be able to
	 * process dates that are encoded in either UTCTime or GeneralizedTime."
	 *
	 * WTF man. thisUpdate is defined in the spec as GeneralizedTime;
	 * not as CMSTime. This requirement makes no sense whatsoever.
	 *
	 * Check the errata?
	 */
	/* manifest->thisUpdate */

	/*
	 * TODO again, same bullshit:
	 *
	 * "CRL issuers conforming to this profile MUST encode nextUpdate as
	 * UTCTime for dates through the year 2049.  CRL issuers conforming to
	 * this profile MUST encode nextUpdate as GeneralizedTime for dates in
	 * the year 2050 or later.  Conforming applications MUST be able to
	 * process dates that are encoded in either UTCTime or GeneralizedTime."
	 */
	/* manifest->nextUpdate */

	/* rfc6486#section-4.4.3 */
	error = validate_dates(&manifest->thisUpdate, &manifest->nextUpdate);
	if (error)
		return error;

	error = is_hash_algorithm(&manifest->fileHashAlg, &is_hash);
	if (error)
		return error;
	if (!is_hash)
		return -EINVAL;

	/* fileList needs no validations for now.*/

	return 0;
}

int manifest_decode(struct SignedData *sdata, struct Manifest **result)
{
	struct Manifest *manifest;
	int error;

	/* rfc6486#section-4.1 */
	/* rfc6486#section-4.4.1 */
	error = validate_eContentType(sdata);
	if (error)
		return error;

	/* rfc6486#section-4.3 */
	error = validate_content_type(sdata);
	if (error)
		return error;

	error = asn1_decode_octet_string(sdata->encapContentInfo.eContent,
	    &asn_DEF_Manifest, (void **) &manifest);
	if (error)
		return -EINVAL;

	error = validate_manifest(manifest);
	if (error) {
		ASN_STRUCT_FREE(asn_DEF_Manifest, manifest);
		return error;
	}

	*result = manifest;
	return 0;
}

void manifest_free(struct Manifest *manifest)
{
	ASN_STRUCT_FREE(asn_DEF_Manifest, manifest);
}
