#include "manifest.h"

#include <errno.h>
#include <libcmscodec/GeneralizedTime.h>
#include <libcmscodec/Manifest.h>

#include "log.h"
#include "thread_var.h"
#include "asn1/decode.h"
#include "asn1/oid.h"
#include "crypto/hash.h"
#include "object/certificate.h"
#include "object/crl.h"
#include "object/roa.h"
#include "object/signed_object.h"

struct manifest {
	struct Manifest *obj;
	char const *file_path;
};

static int
manifest_decode(OCTET_STRING_t *string, void *arg)
{
	return asn1_decode_octet_string(string, &asn_DEF_Manifest, arg);
}

static int
validate_dates(GeneralizedTime_t *this, GeneralizedTime_t *next)
{
#define TM_FMT "%02d/%02d/%02d %02d:%02d:%02d"
#define TM_ARGS(tm)							\
	tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,			\
	tm.tm_hour, tm.tm_min, tm.tm_sec

	time_t thisUpdate;
	time_t nextUpdate;
	time_t now;
	struct tm thisUpdate_tm;
	struct tm nextUpdate_tm;

	/*
	 * BTW: We only need the tm variables for error messages, which are
	 * rarely needed.
	 * So maybe we could get a small performance boost by postponing the
	 * calls to localtime_r().
	 */
	thisUpdate = asn_GT2time(this, &thisUpdate_tm, false);
	nextUpdate = asn_GT2time(next, &nextUpdate_tm, false);

	if (difftime(thisUpdate, nextUpdate) > 0) {
		return pr_err(
		    "Manifest's thisUpdate (" TM_FMT ") > nextUpdate ("
		        TM_FMT ").",
		    TM_ARGS(thisUpdate_tm),
		    TM_ARGS(nextUpdate_tm));
	}

	now = time(NULL);
	if (now == ((time_t) -1))
		return pr_errno(errno, "Error getting the current time");

	if (difftime(now, thisUpdate) < 0) {
		return pr_err(
		    "Manifest is not valid yet. (thisUpdate: " TM_FMT ")",
		    TM_ARGS(thisUpdate_tm));
	}
	if (difftime(now, nextUpdate) > 0) {
		return pr_err(
		    "Manifest is expired. (nextUpdate: " TM_FMT ")",
		    TM_ARGS(nextUpdate_tm));
	}

	return 0;

#undef TM_FMT
#undef TM_ARGS
}

static int
validate_manifest(struct Manifest *manifest)
{
	unsigned long version;
	bool is_sha256;
	int error;

	/* rfc6486#section-4.2.1 */

	/*
	 * BTW:
	 *
	 * "If a "one-time-use" EE certificate is employed to verify a manifest,
	 * the EE certificate MUST have a validity period that coincides with
	 * the interval from thisUpdate to nextUpdate, to prevent needless
	 * growth of the CA's CRL."
	 *
	 * "If a "sequential-use" EE certificate is employed to verify a
	 * manifest, the EE certificate's validity period needs to be no shorter
	 * than the nextUpdate time of the current manifest."
	 *
	 * It would appear that there's no way to tell whether an EE certificate
	 * is "one-time-use" or "sequential-use," so we have no way to validate
	 * this.
	 */

	/* rfc6486#section-4.4.2 */
	if (manifest->version != NULL) {
		error = asn_INTEGER2ulong(manifest->version, &version);
		if (error) {
			if (errno)
				pr_errno(errno, "Error casting manifest version");
			return pr_err("The manifest version isn't a valid unsigned long");
		}
		if (version != 0)
			return -EINVAL;
	}

	/*
	 * "Manifest verifiers MUST be able to handle number values up to
	 * 20 octets."
	 */
	if (manifest->manifestNumber.size > 20)
		return pr_err("Manifest number is larger than 20 octets");

	/* rfc6486#section-4.4.3 */
	error = validate_dates(&manifest->thisUpdate, &manifest->nextUpdate);
	if (error)
		return error;

	/* rfc6486#section-6.6 (I guess) */
	error = hash_is_sha256(&manifest->fileHashAlg, &is_sha256);
	if (error)
		return error;
	if (!is_sha256)
		return pr_err("The hash algorithm is not SHA256.");

	/* The file hashes will be validated during the traversal. */

	return 0;
}

static int
__handle_manifest(struct manifest *mft, struct rpp **pp)
{
	int i;
	struct FileAndHash *fah;
	struct rpki_uri uri;
	int error;

	*pp = rpp_create();
	if (*pp == NULL)
		return pr_enomem();

	for (i = 0; i < mft->obj->fileList.list.count; i++) {
		fah = mft->obj->fileList.list.array[i];

		error = uri_init_mft(&uri, mft->file_path, &fah->file);
		/*
		 * Not handling ENOTRSYNC is fine because the manifest URL
		 * should have been RSYNC. Something went wrong if an RSYNC URL
		 * plus a relative path is not RSYNC.
		 */
		if (error)
			goto fail;

		error = hash_validate_file("sha256", &uri, &fah->hash);
		if (error) {
			uri_cleanup(&uri);
			continue;
		}

		if (uri_has_extension(&uri, ".cer"))
			error = rpp_add_cert(*pp, &uri);
		else if (uri_has_extension(&uri, ".roa"))
			error = rpp_add_roa(*pp, &uri);
		else if (uri_has_extension(&uri, ".crl"))
			error = rpp_add_crl(*pp, &uri);
		else if (uri_has_extension(&uri, ".gbr"))
			error = rpp_add_ghostbusters(*pp, &uri);
		else
			uri_cleanup(&uri); /* ignore it. */

		if (error) {
			uri_cleanup(&uri);
			goto fail;
		} /* Otherwise ownership was transferred to @pp. */
	}

	return 0;

fail:
	rpp_destroy(*pp);
	return error;
}

/**
 * Validates the manifest pointed by @uri, returns the RPP described by it in
 * @pp.
 */
int
handle_manifest(struct rpki_uri const *uri, STACK_OF(X509_CRL) *crls,
    struct rpp **pp)
{
	static OID oid = OID_MANIFEST;
	struct oid_arcs arcs = OID2ARCS("manifest", oid);
	struct signed_object_args sobj_args;
	struct manifest mft;
	int error;

	pr_debug_add("Manifest '%s' {", uri_get_printable(uri));
	fnstack_push_uri(uri);

	error = signed_object_args_init(&sobj_args, uri, crls, false);
	if (error)
		goto end1;
	mft.file_path = uri->global;

	error = signed_object_decode(&sobj_args, &arcs,
	    manifest_decode, &mft.obj);
	if (error)
		goto end2;

	error = validate_manifest(mft.obj);
	if (error)
		goto end3;
	error = __handle_manifest(&mft, pp);
	if (error)
		goto end3;

	error = refs_validate_ee(&sobj_args.refs, *pp, uri);
	if (error)
		rpp_destroy(*pp);

end3:
	ASN_STRUCT_FREE(asn_DEF_Manifest, mft.obj);
end2:
	signed_object_args_cleanup(&sobj_args);
end1:
	pr_debug_rm("}");
	fnstack_pop();
	return error;
}
