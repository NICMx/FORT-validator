#include "object/manifest.h"

#include "alloc.h"
#include "algorithm.h"
#include "asn1/asn1c/GeneralizedTime.h"
#include "asn1/asn1c/Manifest.h"
#include "asn1/decode.h"
#include "asn1/oid.h"
#include "common.h"
#include "hash.h"
#include "log.h"
#include "object/certificate.h"
#include "object/crl.h"
#include "object/roa.h"
#include "object/signed_object.h"
#include "thread_var.h"

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

	now_tt = time_fatal();
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

static bool
is_valid_mft_file_chara(uint8_t chara)
{
	return ('a' <= chara && chara <= 'z')
	    || ('A' <= chara && chara <= 'Z')
	    || ('0' <= chara && chara <= '9')
	    || (chara == '-')
	    || (chara == '_');
}

/* RFC 6486bis, section 4.2.2 */
static int
validate_mft_file(IA5String_t *ia5)
{
	size_t dot;
	size_t i;

	if (ia5->size < 5)
		return pr_val_err("File name is too short (%zu < 5).", ia5->size);
	dot = ia5->size - 4;
	if (ia5->buf[dot] != '.')
		return pr_val_err("File name seems to lack a three-letter extension.");

	for (i = 0; i < ia5->size; i++) {
		if (i != dot && !is_valid_mft_file_chara(ia5->buf[i])) {
			return pr_val_err("File name contains illegal character #%u",
			    ia5->buf[i]);
		}
	}

	/*
	 * Actual extension doesn't matter; if there's no handler,
	 * we'll naturally ignore the file.
	 */
	return 0;
}

///**
// * Computes the hash of the file @map, and compares it to @expected (The
// * "expected" hash).
// *
// * Returns:
// *   0 if no errors happened and the hashes match, or the hash doesn't match
// *     but there's an incidence to ignore such error.
// * < 0 if there was an error that can't be ignored.
// * > 0 if there was an error but it can be ignored (file not found and there's
// *     an incidence to ignore this).
// */
//static int
//hash_validate_mft_file(struct cache_mapping *map, BIT_STRING_t const *expected)
//{
//	struct hash_algorithm const *algorithm;
//	size_t hash_size;
//	unsigned char actual[EVP_MAX_MD_SIZE];
//	int error;
//
//	algorithm = hash_get_sha256();
//	hash_size = hash_get_size(algorithm);
//
//	if (expected->size != hash_size)
//		return pr_val_err("%s string has bogus size: %zu",
//		    hash_get_name(algorithm), expected->size);
//	if (expected->bits_unused != 0)
//		return pr_val_err("Hash string has unused bits.");
//
//	/*
//	 * TODO (#82) This is atrocious. Implement RFC 9286, and probably reuse
//	 * hash_validate_file().
//	 */
//
//	error = hash_file(algorithm, map_get_path(map), actual, NULL);
//	if (error) {
//		if (error == EACCES || error == ENOENT) {
//			/* FIXME .................. */
//			if (incidence(INID_MFT_FILE_NOT_FOUND,
//			    "File '%s' listed at manifest doesn't exist.",
//			    map_val_get_printable(map)))
//				return -EINVAL;
//
//			return error;
//		}
//		/* Any other error (crypto, file read) */
//		return ENSURE_NEGATIVE(error);
//	}
//
//	if (memcmp(expected->buf, actual, hash_size) != 0) {
//		return incidence(INID_MFT_FILE_HASH_NOT_MATCH,
//		    "File '%s' does not match its manifest hash.",
//		    map_val_get_printable(map));
//	}
//
//	return 0;
//}

static int
build_rpp(struct Manifest *mft, char const *mft_url, struct rpp **pp)
{
	char *rpp_url, *slash;
	size_t rpp_url_len;
	int i;
	struct FileAndHash *fah;
	char *file_url;
	size_t file_url_len;
	int written;
	char const *extension;
	int error;

	*pp = rpp_create();

	slash = strrchr(mft_url, '/');
	if (!slash)
		; // XXX
	rpp_url_len = slash - mft_url;
	rpp_url = pstrndup(mft_url, rpp_url_len);

	for (i = 0; i < mft->fileList.list.count; i++) {
		fah = mft->fileList.list.array[i];

		/*
		 * IA5String is a subset of ASCII. However, IA5String_t doesn't
		 * seem to be guaranteed to be NULL-terminated.
		 * `(char *) ia5->buf` is fair, but `strlen(ia5->buf)` is not.
		 */

		error = validate_mft_file(&fah->file);
		if (error)
			; // XXX

		file_url_len = rpp_url_len + fah->file.size + 2;
		file_url = pmalloc(file_url_len);
		written = snprintf(file_url, file_url_len, "%s/%.*s", rpp_url,
		    (int)fah->file.size, fah->file.buf);
		if (written >= file_url_len)
			; // XXX

//		/*
//		 * XXX I think this should be moved somewhere else.
//		 *
//		 * Expect:
//		 * - Negative value: an error not to be ignored, the whole
//		 *   manifest will be discarded.
//		 * - Zero value: hash at manifest matches file's hash, or it
//		 *   doesn't match its hash but there's an incidence to ignore
//		 *   such error.
//		 * - Positive value: file doesn't exist and keep validating
//		 *   manifest.
//		 */
//		error = hash_validate_mft_file(map, &fah->hash);
//		if (error < 0) {
//			free(file_url);
//			goto fail;
//		}
//		if (error > 0) {
//			free(file_url);
//			continue;
//		}

		extension = ((char const *)fah->file.buf) + fah->file.size - 4;
		if (strcmp(extension, ".cer") == 0)
			rpp_add_cert(*pp, file_url);
		else if (strcmp(extension, ".roa") == 0)
			rpp_add_roa(*pp, file_url);
		else if (strcmp(extension, ".crl") == 0) {
			error = rpp_add_crl(*pp, file_url);
			if (error) {
				free(file_url);
				goto fail;
			}
		} else if (strcmp(extension, ".gbr") == 0)
			rpp_add_ghostbusters(*pp, file_url);
		else
			free(file_url); /* ignore it. */
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
 * @pp.
 */
int
handle_manifest(struct cache_mapping *map, struct rpp **pp)
{
	static OID oid = OID_MANIFEST;
	struct oid_arcs arcs = OID2ARCS("manifest", oid);
	struct signed_object sobj;
	struct ee_cert ee;
	struct Manifest *mft;
	STACK_OF(X509_CRL) *crl;
	int error;

	/* Prepare */
	pr_val_debug("Manifest '%s' {", map_val_get_printable(map));
	fnstack_push_map(map);

	/* Decode */
	error = signed_object_decode(&sobj, map->path);
	if (error)
		goto revert_log;
	error = decode_manifest(&sobj, &mft);
	if (error)
		goto revert_sobj;

	/* Initialize out parameter (@pp) */
	error = build_rpp(mft, map->url, pp);
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
	error = refs_validate_ee(&ee.refs, *pp, map->url);
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
	return error;
}
