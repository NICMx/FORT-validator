#include "manifest.h"

#include <errno.h>
#include <libcmscodec/GeneralizedTime.h>
#include <libcmscodec/Manifest.h>

#include "log.h"
#include "thread_var.h"
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
validate_dates(GeneralizedTime_t *this, GeneralizedTime_t *next)
{
	const struct asn_TYPE_descriptor_s *def = &asn_DEF_GeneralizedTime;
	return (GeneralizedTime_compare(def, this, next) < 0) ? 0 : -EINVAL;
}

static int
validate_manifest(struct Manifest *manifest)
{
	bool is_sha256;
	int error;

	/* rfc6486#section-4.2.1 */

	/*
	 * TODO (field)
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
	 * TODO (field)
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
	 * TODO (field) again, same bullshit:
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

	/* rfc6486#section-6.6 (I guess) */
	error = hash_is_sha256(&manifest->fileHashAlg, &is_sha256);
	if (error)
		return error;
	if (!is_sha256)
		return pr_err("The hash algorithm is not SHA256.");

	/* The file hashes will be validated during the traversal. */

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
get_relative_file(char const *mft, char const *file, size_t file_len,
    char **result)
{
	char *joined;
	char *slash_pos;
	int dir_len;

	slash_pos = strrchr(mft, '/');
	if (slash_pos == NULL) {
		joined = malloc(file_len + 1);
		if (!joined)
			return -ENOMEM;
		strncpy(joined, file, file_len);
		joined[file_len] = '\0';
		goto succeed;
	}

	dir_len = (slash_pos + 1) - mft;
	joined = malloc(dir_len + file_len + 1);
	if (!joined)
		return -ENOMEM;

	strncpy(joined, mft, dir_len);
	strncpy(joined + dir_len, file, file_len);
	joined[dir_len + file_len] = '\0';

succeed:
	*result = joined;
	return 0;
}

typedef int (*foreach_cb)(char *, void *);

static int
foreach_file(struct manifest *mft, char *extension, foreach_cb cb, void *arg)
{
	struct FileAndHash *fah;
	char *uri;
	size_t uri_len;
	char *luri; /* "Local URI". As in "URI that we can easily reference." */
	int i;
	int error;

	for (i = 0; i < mft->obj->fileList.list.count; i++) {
		fah = mft->obj->fileList.list.array[i];

		/*
		 * IA5String is just a subset of ASCII, so this cast is fine.
		 * I don't see any guarantees that the string will be
		 * zero-terminated though, so we'll handle that the hard way.
		 */
		uri = (char *) fah->file.buf;
		uri_len = fah->file.size;

		if (file_has_extension(uri, uri_len, extension)) {
			error = get_relative_file(mft->file_path, uri, uri_len,
			    &luri);
			if (error)
				return error;

			error = hash_validate_file("sha256", luri, &fah->hash);
			if (error) {
				free(luri);
				continue;
			}

			error = cb(luri, arg);

			free(luri);
			if (error)
				return error;
		}
	}

	return 0;
}

static int
pile_crls(char *file, void *crls)
{
	X509_CRL *crl;
	int error;
	int idx;

	/* rfc6481#section-2.2 */
	if (sk_X509_CRL_num(crls) != 0)
		return pr_err("The Manifest defines more than one CRL.");

	fnstack_push(file);

	error = crl_load(file, &crl);
	if (error)
		goto end;

	idx = sk_X509_CRL_push(crls, crl);
	if (idx <= 0) {
		error = crypto_err("Could not add CRL to a CRL stack");
		X509_CRL_free(crl);
		goto end;
	}

end:
	fnstack_pop();
	return error;
}

/*
 * Speaking of CA certs: I still don't get the CA/EE cert duality at the
 * implementation level.
 *
 * Right now, I'm assuming that file certs are CA certs, and CMS-embedded certs
 * are EE certs. None of the RFCs seem to mandate this, but I can't think of any
 * other way to interpret it.
 *
 * It's really weird because the RFCs actually define requirements like "other
 * AccessMethods MUST NOT be used for an EE certificates's SIA," (RFC6481) which
 * seems to imply that there's some contextual way to already know whether a
 * certificate is CA or EE. But it just doesn't exist.
 */
static int
traverse_ca_certs(char *file, void *crls)
{
	X509 *cert;

	pr_debug_add("(CA?) Certificate {");
	fnstack_push(file);

	/*
	 * Errors on at least some of these functions should not interrupt the
	 * traversal of sibling nodes, so ignore them.
	 * (Error messages should have been printed in stderr.)
	 */

	if (certificate_load(file, &cert))
		goto revert1; /* Fine */

	if (certificate_validate_chain(cert, crls))
		goto revert2; /* Fine */
	if (certificate_validate_rfc6487(cert, false))
		goto revert2; /* Fine */
	certificate_traverse_ca(cert, crls); /* Error code is useless. */

revert2:
	X509_free(cert);
revert1:
	pr_debug_rm("}");
	fnstack_pop();
	return 0;
}

static int
print_roa(char *file, void *arg)
{
	handle_roa(file, arg);
	return 0;
}

static int
__handle_manifest(struct manifest *mft)
{
	STACK_OF(X509_CRL) *crls;
	int error;

	/* Init */
	crls = sk_X509_CRL_new_null();
	if (crls == NULL)
		return pr_enomem();

	/* Get the one CRL as a stack. */
	error = foreach_file(mft, ".crl", pile_crls, crls);
	if (error)
		goto end;

	/* Use CRL stack to validate certificates, and also traverse them. */
	error = foreach_file(mft, ".cer", traverse_ca_certs, crls);
	if (error)
		goto end;

	/* Use valid address ranges to print ROAs that match them. */
	error = foreach_file(mft, ".roa", print_roa, crls);

end:
	sk_X509_CRL_pop_free(crls, X509_CRL_free);
	return error;
}

int
handle_manifest(char const *file_path, STACK_OF(X509_CRL) *crls)
{
	static OID oid = OID_MANIFEST;
	struct oid_arcs arcs = OID2ARCS(oid);
	struct manifest mft;
	int error;

	pr_debug_add("Manifest %s {", file_path);
	fnstack_push(file_path);

	mft.file_path = file_path;

	error = signed_object_decode(file_path, &asn_DEF_Manifest, &arcs,
	    (void **) &mft.obj, crls, NULL);
	if (error)
		goto end;

	error = validate_manifest(mft.obj);
	if (!error)
		error = __handle_manifest(&mft);

	ASN_STRUCT_FREE(asn_DEF_Manifest, mft.obj);
end:
	pr_debug_rm("}");
	fnstack_pop();
	return error;
}
