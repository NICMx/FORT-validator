#include "object/manifest.h"

#include "algorithm.h"
#include "asn1/asn1c/Manifest.h"
#include "asn1/decode.h"
#include "crypto/hash.h"
#include "log.h"
#include "object/signed_object.h"
#include "thread_var.h"

static int
cage(struct rpki_uri **uri, struct rpki_uri *notif)
{
	if (notif == NULL) {
		/* No need to cage */
		uri_refget(*uri);
		return 0;
	}

	return uri_create_caged(uri,
	    tal_get_file_name(validation_tal(state_retrieve())), notif,
	    uri_get_global(*uri), uri_get_global_len(*uri));
}

static int
decode_manifest(struct signed_object *sobj, struct Manifest **result)
{
	return asn1_decode_octet_string(
		sobj->sdata->encapContentInfo.eContent,
		&asn_DEF_Manifest,
		(void **) result,
		true
	);
}

/*
 * Expects both arguments to be normalized and CST.
 */
static int
tm_cmp(struct tm *tm1, struct tm *tm2)
{
#define TM_CMP(field)							\
	if (tm1->field < tm2->field)					\
		return -1;						\
	if (tm1->field > tm2->field)					\
		return 1;						\

	TM_CMP(tm_year);
	TM_CMP(tm_mon);
	TM_CMP(tm_mday);
	TM_CMP(tm_hour);
	TM_CMP(tm_min);
	TM_CMP(tm_sec);
	return 0;

#undef TM_CMP
}

static int
validate_dates(GeneralizedTime_t *this, GeneralizedTime_t *next)
{
#define TM_FMT "%02d/%02d/%02d %02d:%02d:%02d"
#define TM_ARGS(tm)							\
	tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,			\
	tm.tm_hour, tm.tm_min, tm.tm_sec

	time_t now_tt;
	struct tm now;
	struct tm thisUpdate;
	struct tm nextUpdate;
	int error;

	error = asn_GT2time(this, &thisUpdate);
	if (error)
		return pr_val_err("Manifest's thisUpdate date is unparseable.");
	error = asn_GT2time(next, &nextUpdate);
	if (error)
		return pr_val_err("Manifest's nextUpdate date is unparseable.");

	if (tm_cmp(&thisUpdate, &nextUpdate) > 0) {
		return pr_val_err(
		    "Manifest's thisUpdate (" TM_FMT ") > nextUpdate ("
		        TM_FMT ").",
		    TM_ARGS(thisUpdate),
		    TM_ARGS(nextUpdate));
	}

	now_tt = 0;
	error = get_current_time(&now_tt);
	if (error)
		return error;
	if (gmtime_r(&now_tt, &now) == NULL) {
		error = errno;
		return pr_val_err("gmtime_r(now) error %d: %s", error,
		    strerror(error));
	}

	if (tm_cmp(&now, &thisUpdate) < 0) {
		return pr_val_err(
		    "Manifest is not valid yet. (thisUpdate: " TM_FMT ")",
		    TM_ARGS(thisUpdate));
	}
	if (tm_cmp(&now, &nextUpdate) > 0) {
		return incidence(INID_MFT_STALE,
		    "Manifest is stale. (nextUpdate: " TM_FMT ")",
		    TM_ARGS(nextUpdate));
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

/* Requires list->count > 0 */
static void
shuffle_file_list(struct Manifest *mft)
{
	unsigned int seed, rnd;
	unsigned int i, j;
	struct FileAndHash *tmpfah;

	seed = time(NULL) ^ getpid();

	/* Fisher-Yates shuffle with modulo bias */
	for (i = 0; i < mft->fileList.list.count - 1; i++) {
		rnd = rand_r(&seed);
		j = i + rnd % (mft->fileList.list.count - i);
		tmpfah = mft->fileList.list.array[j];
		mft->fileList.list.array[j] = mft->fileList.list.array[i];
		mft->fileList.list.array[i] = tmpfah;
	}
}

/*
 * Contract:
 * - Length = 4 (includes dot)
 * - Not NULL-terminated!
 * - Can return NULL
 */
static char *
get_extension(IA5String_t *file)
{
	return (file->size < 4) ? NULL : (((char *)file->buf) + file->size - 4);
}

static int
build_rpp(struct Manifest *mft, struct rpki_uri *notif,
    struct rpki_uri *mft_uri, struct rpp **pp)
{
	char const *tal;
	unsigned int i;
	struct FileAndHash *fah;
	char *ext;
	int (*rpp_add)(struct rpp *pp, struct rpki_uri *uri);
	struct rpki_uri *uri;
	int error;

	if (mft->fileList.list.count == 0)
		return pr_val_err("Manifest's file list is empty.");

	shuffle_file_list(mft);

	*pp = rpp_create();
	tal = tal_get_file_name(validation_tal(state_retrieve()));

	for (i = 0; i < mft->fileList.list.count; i++) {
		fah = mft->fileList.list.array[i];

		/*
		 * rsync filters unknown files. We don't want absent unknown
		 * files to induce RPP rejection, so we'll skip them.
		 * This contradicts rfc9286#6.4, but it's necessary evil because
		 * we can't trust the repositories to not accidentally serve
		 * garbage.
		 *
		 * This includes .mft; They're presently not supposed to be
		 * listed.
		 */
		ext = get_extension(&fah->file);
		if (ext == NULL)
			continue;
		else if (strncmp(ext, ".cer", 4) == 0)
			rpp_add = rpp_add_cer;
		else if (strncmp(ext, ".roa", 4) == 0)
			rpp_add = rpp_add_roa;
		else if (strncmp(ext, ".crl", 4) == 0)
			rpp_add = rpp_add_crl;
		else if (strncmp(ext, ".gbr", 4) == 0)
			rpp_add = rpp_add_gbr;
		else
			continue;

		error = uri_create_mft(&uri, tal, notif, mft_uri, &fah->file);
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

		error = rpp_add(*pp, uri);
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
handle_manifest(struct rpki_uri *uri, struct rpki_uri *notif, struct rpp **pp)
{
	static OID oid = OID_MANIFEST;
	struct oid_arcs arcs = OID2ARCS("manifest", oid);
	struct signed_object sobj;
	struct ee_cert ee;
	struct Manifest *mft;
	STACK_OF(X509_CRL) *crl;
	int error;

	/* Prepare */
	error = cage(&uri, notif); /* ref++ */
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
	error = build_rpp(mft, notif, uri, pp);
	if (error)
		goto revert_manifest;

	/* Prepare validation arguments */
	error = rpp_crl(*pp, &crl);
	if (error)
		goto revert_rpp;
	eecert_init(&ee, crl, false);

	/* Validate everything */
	error = signed_object_validate(&sobj, &arcs, &ee);
	if (error)
		goto revert_args;
	error = validate_manifest(mft);
	if (error)
		goto revert_args;
	error = refs_validate_ee(&ee.refs, *pp, uri);
	if (error)
		goto revert_args;

	/* Success */
	eecert_cleanup(&ee);
	goto revert_manifest;

revert_args:
	eecert_cleanup(&ee);
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
