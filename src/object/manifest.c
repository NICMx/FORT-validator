#include "manifest.h"

#include <errno.h>
#include <libcmscodec/Manifest.h>

#include "common.h"
#include "log.h"
#include "asn1/oid.h"
#include "object/certificate.h"
#include "object/crl.h"
#include "object/roa.h"
#include "object/signed_object.h"

/* TODO not being called right now. */
bool
is_manifest(char const *file_name)
{
	return file_has_extension(file_name, "mft");
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
	static const OID sha_oid = OID_SHA256;
	struct oid_arcs arcs;
	int error;

	error = oid2arcs(aid, &arcs);
	if (error)
		return error;

	*result = ARCS_EQUAL_OIDS(&arcs, sha_oid);

	free_arcs(&arcs);
	return 0;
}

static int
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

/**
 * Given manifest path @mft and its referenced file @file, returns a path
 * @file can be accessed with.
 *
 * ie. if @mft is "a/b/c.mft" and @file is "d/e/f.cer", returns "a/b/d/e/f.cer".
 *
 * The result needs to be freed in the end.
 */
static int
get_relative_file(char const *mft, char const *file, char **result)
{
	char *joined;
	char *slash_pos;
	int dir_len;

	slash_pos = strrchr(mft, '/');
	if (slash_pos == NULL) {
		joined = malloc(strlen(file) + 1);
		if (!joined)
			return -ENOMEM;
		strcpy(joined, file);
		goto succeed;
	}

	dir_len = (slash_pos + 1) - mft;
	joined = malloc(dir_len + strlen(file) + 1);
	if (!joined)
		return -ENOMEM;

	strncpy(joined, mft, dir_len);
	strcpy(joined + dir_len, file);

succeed:
	*result = joined;
	return 0;
}

static int
handle_file(struct validation *state, char const *mft, IA5String_t *string)
{
	char *luri;
	int error;

	/* TODO Treating string->buf as a C string is probably not correct. */
//	pr_debug_add(state, "File %s {", string->buf);

	error = get_relative_file(mft, (char const *) string->buf, &luri);
	if (error)
		goto end;

	pr_debug_add(state, "File %s {", luri);

	if (is_certificate(luri))
		error = certificate_handle(state, luri);
	else if (is_crl(luri))
		error = handle_crl(state, luri);
	else if (is_roa(luri))
		error = handle_roa(state, luri);
	else
		pr_debug(state, "Unhandled file type.");

	free(luri);
end:
	pr_debug_rm(state, "}");
	return error;
}

static int
__handle_manifest(struct validation *state, char const *mft,
    struct Manifest *manifest)
{
	int i;
	int error;

	for (i = 0; i < manifest->fileList.list.count; i++) {
		error = handle_file(state, mft,
		    &manifest->fileList.list.array[i]->file);
		if (error)
			return error;
	}

	return 0;
}

int
handle_manifest(struct validation *state, char const *file_path)
{
	static OID oid = OID_MANIFEST;
	struct oid_arcs arcs = OID2ARCS(oid);
	struct Manifest *manifest;
	int error;

	error = signed_object_decode(state, file_path, &asn_DEF_Manifest, &arcs,
	    (void **) &manifest);
	if (error)
		return error;

	error = validate_manifest(manifest);
	if (!error)
		error = __handle_manifest(state, file_path, manifest);

	ASN_STRUCT_FREE(asn_DEF_Manifest, manifest);
	return error;
}
