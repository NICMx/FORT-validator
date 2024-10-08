#include "object/manifest.h"

#include "algorithm.h"
#include "alloc.h"
#include "asn1/asn1c/Manifest.h"
#include "asn1/decode.h"
#include "common.h"
#include "config.h"
#include "hash.h"
#include "log.h"
#include "object/crl.h"
#include "object/signed_object.h"
#include "thread_var.h"
#include "types/path.h"
#include "types/url.h"

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

	now_tt = config_get_validation_time();
	if (now_tt == 0)
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

static void
shuffle_mft_files(struct Manifest *mft)
{
	int i, j;
	unsigned int seed, rnd;
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
validate_mft_filename(IA5String_t *ia5)
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
build_rpp(char const *mft_url, struct Manifest *mft, struct cache_cage *cage,
    struct rpki_certificate *parent)
{
	struct rpp *rpp;
	char *rpp_url;
	unsigned int i;
	struct FileAndHash *src;
	struct cache_mapping *dst;
	char const *path;
	int error;

	shuffle_mft_files(mft);

	rpp = &parent->rpp;
	rpp_url = url_parent(mft_url); // XXX
	rpp->nfiles = mft->fileList.list.count;
	rpp->files = pzalloc(rpp->nfiles * sizeof(*rpp->files));

	for (i = 0; i < mft->fileList.list.count; i++) {
		src = mft->fileList.list.array[i];
		dst = &rpp->files[i];

		/*
		 * IA5String is a subset of ASCII. However, IA5String_t doesn't
		 * seem to be guaranteed to be NULL-terminated.
		 */

		error = validate_mft_filename(&src->file);
		if (error)
			goto revert;

		dst->url = path_njoin(rpp_url,
		    (char const *)src->file.buf,
		    src->file.size);

		path = cage_map_file(cage, dst->url);
		if (!path) {
			error = pr_val_err(
			    "Manifest file '%s' is absent from the cache.",
			    dst->url);
			goto revert;
		}
		dst->path = pstrdup(path);

		error = check_file_and_hash(src, dst->path);
		if (error)
			goto revert;

		if (strcmp(((char const *)src->file.buf) + src->file.size - 4, ".crl") == 0) {
			if (rpp->crl.map != NULL) {
				error = pr_val_err(
				    "Manifest has more than one CRL.");
				goto revert;
			}
			rpp->crl.map = dst;
		}
	}

	/* rfc6486#section-7 */
	if (rpp->crl.map == NULL) {
		error = pr_val_err("Manifest lacks a CRL.");
		goto revert;
	}

	error = crl_load(rpp->crl.map, parent->x509, &rpp->crl.obj);
	if (error)
		goto revert;

	free(rpp_url);
	return 0;

revert:	rpp_cleanup(rpp);
	free(rpp_url);
	return error;
}

int
manifest_traverse(char const *url, char const *path, struct cache_cage *cage,
    struct rpki_certificate *parent)
{
	static OID oid = OID_MANIFEST;
	struct oid_arcs arcs = OID2ARCS("manifest", oid);
	struct signed_object sobj;
	struct rpki_certificate ee;
	struct Manifest *mft;
	int error;

	/* Prepare */
	fnstack_push(url); // XXX

	/* Decode */
	error = signed_object_decode(&sobj, path);
	if (error)
		goto end1;
	error = decode_manifest(&sobj, &mft);
	if (error)
		goto end2;

	/* Initialize @summary */
	error = build_rpp(url, mft, cage, parent);
	if (error)
		goto end3;

	/* Prepare validation arguments */
	rpki_certificate_init_ee(&ee, parent, false);

	/* Validate everything */
	error = signed_object_validate(&sobj, &arcs, &ee);
	if (error)
		goto end5;
	error = validate_manifest(mft);
	if (error)
		goto end5;
	error = refs_validate_ee(&ee.sias, parent->rpp.crl.map->url, url);

end5:	rpki_certificate_cleanup(&ee);
	if (error)
		rpp_cleanup(&parent->rpp);
end3:	ASN_STRUCT_FREE(asn_DEF_Manifest, mft);
end2:	signed_object_cleanup(&sobj);
end1:	fnstack_pop();
	return error;
}
