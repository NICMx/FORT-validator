#include "object/manifest.h"

#include <errno.h>

#include "algorithm.h"
#include "common.h"
#include "log.h"
#include "thread_var.h"
#include "asn1/decode.h"
#include "asn1/oid.h"
#include "asn1/asn1c/GeneralizedTime.h"
#include "asn1/asn1c/Manifest.h"
#include "crypto/hash.h"
#include "object/certificate.h"
#include "object/crl.h"
#include "object/roa.h"
#include "object/signed_object.h"

static int
cage(struct rpki_uri **uri)
{
	if (validation_get_notification_uri(state_retrieve()) == NULL) {
		/* No need to cage */
		uri_refget(*uri);
		return 0;
	}

	return __uri_create(uri, UT_CAGED, uri_get_global(*uri),
	    uri_get_global_len(*uri));
}

static int
decode_manifest(struct signed_object *sobj, struct Manifest **result)
{
	return asn1_decode_octet_string(
		sobj->sdata.decoded->encapContentInfo.eContent,
		&asn_DEF_Manifest,
		(void **) result,
		true,
		false
	);
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
	int error;

	/*
	 * BTW: We only need the tm variables for error messages, which are
	 * rarely needed.
	 * So maybe we could get a small performance boost by postponing the
	 * calls to localtime_r().
	 */
	thisUpdate = asn_GT2time(this, &thisUpdate_tm, false);
	nextUpdate = asn_GT2time(next, &nextUpdate_tm, false);

	if (difftime(thisUpdate, nextUpdate) > 0) {
		return pr_val_err(
		    "Manifest's thisUpdate (" TM_FMT ") > nextUpdate ("
		        TM_FMT ").",
		    TM_ARGS(thisUpdate_tm),
		    TM_ARGS(nextUpdate_tm));
	}

	now = 0;
	error = get_current_time(&now);
	if (error)
		return error;

	if (difftime(now, thisUpdate) < 0) {
		return pr_val_err(
		    "Manifest is not valid yet. (thisUpdate: " TM_FMT ")",
		    TM_ARGS(thisUpdate_tm));
	}
	if (difftime(now, nextUpdate) > 0) {
		return incidence(INID_MFT_STALE,
		    "Manifest is stale. (nextUpdate: " TM_FMT ")",
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
			if (errno) {
				pr_val_err("Error casting manifest version: %s",
				    strerror(errno));
			}
			return pr_val_err("The manifest version isn't a valid unsigned long");
		}
		if (version != 0)
			return -EINVAL;
	}

	/*
	 * "Manifest verifiers MUST be able to handle number values up to
	 * 20 octets."
	 */
	if (manifest->manifestNumber.size > 20)
		return pr_val_err("Manifest number is larger than 20 octets");

	/* rfc6486#section-4.4.3 */
	error = validate_dates(&manifest->thisUpdate, &manifest->nextUpdate);
	if (error)
		return error;

	/* rfc6486#section-4.2.1.fileHashAlg */
	/*
	 * Um, RFC 7935 does not declare a hash algorithm specifically intended
	 * for manifest hashes. But all the hashes it declares are SHA256, so
	 * I guess we'll just default to that.
	 * I'm going with the signed object hash function, since it appears to
	 * be the closest match.
	 */
	error = validate_cms_hashing_algorithm_oid(&manifest->fileHashAlg,
	    "manifest file");
	if (error)
		return error;

	/* The file hashes will be validated during the traversal. */

	return 0;
}

static int
build_rpp(struct Manifest *mft, struct rpki_uri *mft_uri, struct rpp **pp)
{
	int i;
	struct FileAndHash *fah;
	struct rpki_uri *uri;
	int error;

	*pp = rpp_create();
	if (*pp == NULL)
		enomem_panic();

	for (i = 0; i < mft->fileList.list.count; i++) {
		fah = mft->fileList.list.array[i];

		error = uri_create_mft(&uri, mft_uri, &fah->file);
		/*
		 * Not handling ENOTRSYNC is fine because the manifest URL
		 * should have been RSYNC. Something went wrong if an RSYNC URL
		 * plus a relative path is not RSYNC.
		 */
		if (error)
			goto fail;

		/*
		 * Expect:
		 * - Negative value: an error not to be ignored, the whole
		 *   manifest will be discarded.
		 * - Zero value: hash at manifest matches file's hash, or it
		 *   doesn't match its hash but there's an incidence to ignore
		 *   such error.
		 * - Positive value: file doesn't exist and keep validating
		 *   manifest.
		 */
		error = hash_validate_mft_file(uri, &fah->hash);
		if (error < 0) {
			uri_refput(uri);
			goto fail;
		}
		if (error > 0) {
			uri_refput(uri);
			continue;
		}

		if (uri_has_extension(uri, ".cer"))
			rpp_add_cert(*pp, uri);
		else if (uri_has_extension(uri, ".roa"))
			rpp_add_roa(*pp, uri);
		else if (uri_has_extension(uri, ".crl"))
			error = rpp_add_crl(*pp, uri);
		else if (uri_has_extension(uri, ".gbr"))
			rpp_add_ghostbusters(*pp, uri);
		else
			uri_refput(uri); /* ignore it. */

		if (error) {
			uri_refput(uri);
			goto fail;
		} /* Otherwise ownership was transferred to @pp. */
	}

	/* rfc6486#section-7 */
	if (rpp_get_crl(*pp) == NULL) {
		error = pr_val_err("Manifest lacks a CRL.");
		goto fail;
	}

	return 0;

fail:
	rpp_refput(*pp);
	return error;
}

/**
 * Validates the manifest pointed by @uri, returns the RPP described by it in
 * @pp. If @rrdp_workspace is true, use the local RRDP repository.
 */
int
handle_manifest(struct rpki_uri *uri, struct rpp **pp)
{
	static OID oid = OID_MANIFEST;
	struct oid_arcs arcs = OID2ARCS("manifest", oid);
	struct signed_object sobj;
	struct signed_object_args sobj_args;
	struct Manifest *mft;
	STACK_OF(X509_CRL) *crl;
	int error;

	/* Prepare */
	error = cage(&uri); /* ref++ */
	if (error)
		return error;
	pr_val_debug("Manifest '%s' {", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	/* Decode */
	error = signed_object_decode(&sobj, uri);
	if (error)
		goto revert_log;
	error = decode_manifest(&sobj, &mft);
	if (error)
		goto revert_sobj;

	/* Initialize out parameter (@pp) */
	error = build_rpp(mft, uri, pp);
	if (error)
		goto revert_manifest;

	/* Prepare validation arguments */
	error = rpp_crl(*pp, &crl);
	if (error)
		goto revert_rpp;
	signed_object_args_init(&sobj_args, uri, crl, false);

	/* Validate everything */
	error = signed_object_validate(&sobj, &arcs, &sobj_args);
	if (error)
		goto revert_args;
	error = validate_manifest(mft);
	if (error)
		goto revert_args;
	error = refs_validate_ee(&sobj_args.refs, *pp, uri);
	if (error)
		goto revert_args;

	/* Success */
	signed_object_args_cleanup(&sobj_args);
	goto revert_manifest;

revert_args:
	signed_object_args_cleanup(&sobj_args);
revert_rpp:
	rpp_refput(*pp);
revert_manifest:
	ASN_STRUCT_FREE(asn_DEF_Manifest, mft);
revert_sobj:
	signed_object_cleanup(&sobj);
revert_log:
	pr_val_debug("}");
	fnstack_pop();
	uri_refput(uri); /* ref-- */
	return error;
}
