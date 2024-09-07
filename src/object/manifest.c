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
#include "types/path.h"

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

/* RFC 9286, section 4.2.2 */
static int
validate_mft_file(IA5String_t *ia5)
{
	size_t dot;
	size_t i;

	if (ia5->size < 5)
		return pr_val_err("File name is too short (%zu < 5).", ia5->size);
	dot = ia5->size - 4;
	if (ia5->buf[dot] != '.')
		return pr_val_err("File name is missing three-letter extension.");

	for (i = 0; i < ia5->size; i++)
		if (i != dot && !is_valid_mft_file_chara(ia5->buf[i]))
			return pr_val_err("File name contains illegal character #%u",
			    ia5->buf[i]);

	/*
	 * Well... the RFC says the extension must match a IANA listing,
	 * but rejecting unknown extensions is a liability since they keep
	 * adding new ones, and people rarely updates.
	 * If we don't have a handler, we'll naturally ignore the file.
	 */
	return 0;
}

static int
check_file_and_hash(struct FileAndHash *fah, char const *path)
{
	if (fah->hash.bits_unused != 0)
		return pr_val_err("Hash string has unused bits.");

	/* Includes file exists validation, obv. */
	return hash_validate_file(hash_get_sha256(), path,
	    fah->hash.buf, fah->hash.size);
}

#define INFER_CHILD(parent, fah) \
	path_childn(parent, (char const *)fah->file.buf, fah->file.size)

/*
 * XXX
 *
 * revoked manifest: 6.6
 * CRL not in fileList: 6.6
 * fileList file in different folder: 6.6
 * manifest is identified by id-ad-rpkiManifest. (A directory will have more
 * than 1 on rollover.)
 * id-ad-rpkiManifest not found: 6.6
 * invalid manifest: 6.6
 * stale manifest: 6.6
 * fileList file not found: 6.6
 * bad hash: 6.6
 * 6.6: warning, fallback to previous version. Children inherit this.
 */

static int
build_rpp(struct cache_mapping *mft_map, struct Manifest *mft,
    struct rpp **result)
{
	struct cache_mapping pp_map;
	struct rpp *pp;
	int i;
	struct FileAndHash *fah;
	struct cache_mapping map;
	int error;

	map_parent(mft_map, &pp_map);
	pp = rpp_create();

	for (i = 0; i < mft->fileList.list.count; i++) {
		fah = mft->fileList.list.array[i];

		/*
		 * IA5String is a subset of ASCII. However, IA5String_t doesn't
		 * seem to be guaranteed to be NULL-terminated.
		 */

		error = validate_mft_file(&fah->file);
		if (error)
			goto fail;

		map.url = INFER_CHILD(pp_map.url, fah);
		map.path = INFER_CHILD(pp_map.path, fah);

		error = check_file_and_hash(fah, map.path);
		if (error)
			goto fail;

		error = rpp_add_file(pp, &map);
		if (error)
			goto fail;
	}

	/* rfc6486#section-7 */
	if (rpp_crl(pp) == NULL) {
		error = pr_val_err("Manifest lacks a CRL.");
		goto fail;
	}

	map_cleanup(&pp_map);
	*result = pp;
	return 0;

fail:	map_cleanup(&pp_map);
	rpp_refput(pp);
	return error;
}

/* Validates the manifest @map, returns the RPP described by it in @pp. */
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

	/* Initialize @pp */
	error = build_rpp(map, mft, pp);
	if (error)
		goto revert_manifest;

	/* Prepare validation arguments */
	crl = rpp_crl(*pp);
	if (crl == NULL) {
		error = -EINVAL;
		goto revert_rpp;
	}
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
