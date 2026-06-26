#define _DEFAULT_SOURCE  1	/* timegm() on Linux */
#define _DARWIN_C_SOURCE 1	/* timegm() on MacOS */

#include "object/manifest.h"

#include "algorithm.h"
#include "asn1/asn1c/Manifest.h"
#include "asn1/decode.h"
#include "config.h"
#include "hash.h"
#include "log.h"
#include "object/certificate.h"
#include "object/crl.h"
#include "object/signed_object.h"
#include "thread_var.h"

static int
decode_manifest(struct signed_object *so, struct Manifest **result)
{
	return asn1_decode_octet_string(
		so->sdata->encapContentInfo.eContent,
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
validate_dates(GeneralizedTime_t *this, GeneralizedTime_t *next,
    struct mft_meta *meta)
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
		return pr_err("Manifest's thisUpdate date is unparseable.");
	error = asn_GT2time(next, &nextUpdate);
	if (error)
		return pr_err("Manifest's nextUpdate date is unparseable.");

	if (tm_cmp(&thisUpdate, &nextUpdate) > 0) {
		return pr_err(
		    "Manifest's thisUpdate (" TM_FMT ") > nextUpdate ("
		        TM_FMT ").",
		    TM_ARGS(thisUpdate),
		    TM_ARGS(nextUpdate));
	}

	now_tt = config_get_validation_time();
	if (now_tt == 0)
		now_tt = time_fatal();

	if (gmtime_r(&now_tt, &now) == NULL)
		return pr_err("gmtime_r(now) error: %s", strerror(errno));

	if (tm_cmp(&now, &thisUpdate) < 0) {
		return pr_err(
		    "Manifest is not valid yet. (thisUpdate: " TM_FMT ")",
		    TM_ARGS(thisUpdate));
	}
	if (tm_cmp(&now, &nextUpdate) > 0) {
		return pr_err("Manifest is stale. (nextUpdate: " TM_FMT ")",
		    TM_ARGS(nextUpdate));
	}

	meta->update = timegm(&thisUpdate);
	if (meta->update == (time_t)-1)
		return pr_err("Cannot convert '" TM_FMT "' to time_t: %s",
		    TM_ARGS(thisUpdate), strerror(errno));

	return 0;

#undef TM_FMT
#undef TM_ARGS
}

static struct mft_meta const *
max_mftnum(struct mft_meta const *m1, struct mft_meta const *m2)
{
	return INTEGER_cmp(&m1->num, &m2->num) < 0 ? m2 : m1;
}

static int
check_more_recent(struct rpp_querier *querier, struct mft_meta *current)
{
	struct mft_meta const *rrdp;
	struct mft_meta const *rsync;
	struct mft_meta const *prev;
	char *nstr, *ostr;
	int error;

	querier_get_fallback_mftnums(querier, &rrdp, &rsync);

	if (rrdp)
		prev = rsync ? max_mftnum(rrdp, rsync) : rrdp;
	else if (rsync)
		prev = rsync;
	else
		return 0;

	if (memcmp(prev->file->hash, current->file->hash, SHA256_DIGEST_LENGTH) == 0)
		return 0;

	if (prev->num.size && INTEGER_cmp(&prev->num, &current->num) >= 0) {
		nstr = INTEGER_to_str(&current->num);
		ostr = INTEGER_to_str(&prev->num);
		error = pr_err("New manifestNumber (%s) is not higher than fallback manifestNumber (%s).",
		    nstr, ostr);
		free(nstr);
		free(ostr);
		return error;
	}
	if (prev->update && difftime(prev->update, current->update) >= 0)
		return pr_err("New manifest thisUpdate is not newer than the fallback manifest thisUpdate.");

	return 0;
}

static int
validate_manifest(struct Manifest *mft, struct rpp_querier *querier,
    struct mft_meta *meta)
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
	if (mft->version != NULL) {
		error = asn_INTEGER2ulong(mft->version, &version);
		if (error) {
			if (errno) {
				pr_err("Error casting manifest version: %s",
				    strerror(errno));
			}
			return pr_err("The manifest version isn't a valid unsigned long");
		}
		if (version != 0)
			return EINVAL;
	}

	/*
	 * "Manifest verifiers MUST be able to handle number values up to
	 * 20 octets."
	 */
	if (mft->manifestNumber.size > 20)
		return pr_err("Manifest number is larger than 20 octets");
	INTEGER_move(&meta->num, &mft->manifestNumber);

	/* rfc6486#section-4.4.3 */
	error = validate_dates(&mft->thisUpdate, &mft->nextUpdate, meta);
	if (error)
		return error;

	error = check_more_recent(querier, meta);
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
	error = validate_cms_hash_algorithm_oid(&mft->fileHashAlg,
	    "manifest file");
	if (error)
		return error;

	/* The file hashes will be validated during the traversal. */

	return 0;
}

static void
shuffle_mft_files(struct rpp *rpp)
{
	size_t i, j;
	unsigned int seed, rnd;
	struct cache_file *tmp;

	if (rpp->nfiles < 2)
		return;

	seed = time(NULL) ^ getpid();

	/* Fisher-Yates shuffle with modulo bias */
	for (i = 0; i < rpp->nfiles - 1; i++) {
		rnd = rand_r(&seed);
		j = i + rnd % (rpp->nfiles - i);
		tmp = rpp->files[j];
		rpp->files[j] = rpp->files[i];
		rpp->files[i] = tmp;
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
		return pr_err("File name is too short (%zu < 5).", ia5->size);
	dot = ia5->size - 4;
	if (ia5->buf[dot] != '.')
		return pr_err("File name is missing three-letter extension.");

	for (i = 0; i < ia5->size; i++)
		if (i != dot && !is_valid_mft_file_chara(ia5->buf[i]))
			return pr_err("File name contains illegal character #%u",
			    ia5->buf[i]);

	return 0;
}

static int
check_file_and_hash(struct FileAndHash *fah, struct cache_file *file)
{
	if (fah->hash.bits_unused != 0)
		return pr_err("Hash string has unused bits.");
	if (fah->hash.size != SHA256_DIGEST_LENGTH)
		return pr_err("The hash of file '%.*s' has %zu bytes (%d expected).",
		    (int)fah->file.size, fah->file.buf,
		    fah->hash.size, SHA256_DIGEST_LENGTH);

	if (memcmp(fah->hash.buf, file->hash, SHA256_DIGEST_LENGTH) != 0)
		pr_panic("File '%.*s' does not match its expected hash.",
		    (int)fah->file.size, fah->file.buf);

	return 0;
}

static enum file_type
ext2ft(IA5String_t *file)
{
	char const *ext = ((char const *)file->buf) + file->size - 3;

	if (ext[0] == 'c' && ext[1] == 'e' && ext[2] == 'r')
		return FT_CER;
	if (ext[0] == 'r' && ext[1] == 'o' && ext[2] == 'a')
		return FT_ROA;
	if (ext[0] == 'c' && ext[1] == 'r' && ext[2] == 'l')
		return FT_CRL;
	if (ext[0] == 'g' && ext[1] == 'b' && ext[2] == 'r')
		return FT_GBR;

	return FT_UNK;
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
collect_files(struct cache_mapping const *map,
    struct Manifest *mft, struct rpp_querier *querier,
    struct rpki_certificate *parent)
{
	struct rpp *rpp;
	struct uri rpp_url;
	unsigned int m;
	struct FileAndHash *src;
	struct uri url;
	struct cache_file *file;
	enum file_type ft;
	int error;

	if (mft->fileList.list.count == 0)
		return pr_err("Manifest's file list is empty.");

	rpp = &parent->rpp;
	error = uri_parent(&map->url, &rpp_url);
	if (error)
		return error;
	rpp->files = pcalloc(mft->fileList.list.count + 1, sizeof(struct cache_file *));
	rpp->nfiles = 0;

	for (m = 0; m < mft->fileList.list.count; m++) {
		src = mft->fileList.list.array[m];

		/*
		 * IA5String is a subset of ASCII. However, IA5String_t doesn't
		 * seem to be guaranteed to be NULL-terminated.
		 */

		error = validate_mft_filename(&src->file);
		if (error)
			goto revert;

		ft = ext2ft(&src->file);
		/*
		 * rsync and RRDP filter unknown files. We don't want absent
		 * unknown files to induce RPP rejection, so we'll skip them.
		 * This contradicts rfc9286#6.4, but it's necessary evil because
		 * we can't trust the repositories to not accidentally serve
		 * garbage.
		 *
		 * This includes .mft; They're presently not supposed to be
		 * listed.
		 */
		if (ft == FT_UNK)
			continue;

		uri_child(&rpp_url, (char const *)src->file.buf, src->file.size,
		    &url);

		file = querier_map(querier, &url);
		if (!file) {
			error = pr_err(
			    "Manifest file '%s' is absent from the cache.",
			    uri_str(&url));
			uri_cleanup(&url);
			goto revert;
		}

		uri_cleanup(&url);
		rpp->files[rpp->nfiles++] = file;

		error = check_file_and_hash(src, file);
		if (error)
			goto revert;

		if (ft == FT_CRL) {
			if (rpp->crl.file != NULL) {
				error = pr_err("Manifest has more than one CRL.");
				goto revert;
			}
			rpp->crl.file = file;
		}
	}

	/* rfc6486#section-7 */
	if (rpp->crl.file == NULL) {
		error = pr_err("Manifest lacks a CRL.");
		goto revert;
	}

	/* Manifest */
	file = querier_map(querier, &map->url);
	if (!file) {
		error = pr_err("Manifest file '%s' is absent from the cache.",
		    uri_str(&map->url));
		goto revert;
	}
	rpp->files[rpp->nfiles++] = file;
	rpp->mft.file = file;

	return crl_load(&parent->rpp.crl.file->map, parent->x509,
	    &parent->rpp.crl.obj);

revert:	rpp_cleanup(rpp);
	return error;
}

static int
build_rpp(struct cache_mapping const *map, struct Manifest *mft,
    struct rpp_querier *querier, struct rpki_certificate *parent)
{
	int error;

	error = collect_files(map, mft, querier, parent);
	if (error)
		return error;

	shuffle_mft_files(&parent->rpp);
	return 0;
}

int
manifest_traverse(struct cache_mapping const *map, struct rpp_querier *querier,
    struct rpki_certificate *parent)
{
	static OID oid = OID_MANIFEST;
	struct oid_arcs arcs = OID2ARCS("manifest", oid);
	struct signed_object so;
	struct rpki_certificate ee;
	struct Manifest *mft;
	int error;

	/* Prepare */
	pr_trc("Checking MFT: %s", uri_str(&map->url));
	fnstack_push_map(map);

	/* Decode */
	error = signed_object_decode(&so, map);
	if (error)
		goto end1;
	error = decode_manifest(&so, &mft);
	if (error)
		goto end2;

	/* Initialize @summary */
	error = build_rpp(map, mft, querier, parent);
	if (error)
		goto end3;

	/* Prepare validation arguments */
	cer_init_ee(&ee, parent, false);

	/* Validate everything */
	error = signed_object_validate(&so, &ee, &arcs);
	if (error)
		goto end5;
	error = validate_manifest(mft, querier, &parent->rpp.mft);

end5:	cer_cleanup(&ee);
	if (error)
		rpp_cleanup(&parent->rpp);
end3:	ASN_STRUCT_FREE(asn_DEF_Manifest, mft);
end2:	signed_object_cleanup(&so);
end1:	fnstack_pop();
	pr_trc("MFT done.");
	return error;
}
