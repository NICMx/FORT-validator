#include "manifest.h"

#include <errno.h>
#include <libcmscodec/Manifest.h>

#include "common.h"
#include "log.h"
#include "resource.h"
#include "asn1/oid.h"
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

typedef int (*foreach_cb)(struct validation *, char *, void *);

struct foreach_args {
	STACK_OF(X509_CRL) *crls;
	struct resources *resources;
};

static int
foreach_file(struct validation *state, struct manifest *mft, char *extension,
    foreach_cb cb, void *arg)
{
	char *uri;
	char *luri; /* "Local URI". As in "URI that we can easily reference." */
	int i;
	int error;

	for (i = 0; i < mft->obj->fileList.list.count; i++) {
		/* TODO This cast is probably not correct. */
		uri = (char *) mft->obj->fileList.list.array[i]->file.buf;

		if (file_has_extension(uri, extension)) {
			error = get_relative_file(mft->file_path, uri, &luri);
			if (error)
				return error;
			error = cb(state, luri, arg);
			free(luri);
			if (error)
				return error;
		}
	}

	return 0;
}

static int
pile_crls(struct validation *state, char *file, void *crls)
{
	X509_CRL *crl;
	int error;
	int idx;

	error = crl_load(state, file, &crl);
	if (error)
		return error;

	idx = sk_X509_CRL_push(crls, crl);
	if (idx <= 0) {
		error = crypto_err(state, "Could not add CRL to a CRL stack");
		X509_CRL_free(crl);
		return error;
	}

	return 0;
}

static int
pile_addr_ranges(struct validation *state, char *file, void *__args)
{
	struct foreach_args *args = __args;
	struct resources *resources;
	X509 *cert;
	int error = 0;

	pr_debug_add("Certificate {");

	/*
	 * Errors on some of these functions should not interrupt the tree
	 * traversal, so ignore them.
	 * (Error messages should have been printed in stderr.)
	 */

	if (certificate_load(state, file, &cert))
		goto end; /* Fine */

	if (certificate_validate(state, cert, args->crls))
		goto revert; /* Fine */

	resources = resources_create();
	if (resources == NULL) {
		error = -ENOMEM; /* Not fine */
		goto revert;
	}

	if (certificate_get_resources(state, cert, resources))
		goto revert2; /* Fine */

	if (validation_push_cert(state, cert, resources)) {
		/*
		 * Validation_push_cert() only fails on OPENSSL_sk_push().
		 * The latter really only fails on memory allocation fault.
		 * That's grounds to interrupt tree traversal.
		 */
		error = -EINVAL; /* Not fine */
		goto revert2;
	}
	certificate_traverse(state, cert); /* Error code is useless. */
	validation_pop_cert(state); /* Error code is useless. */

	error = resources_join(args->resources, resources); /* Not fine */

revert2:
	resources_destroy(resources);
revert:
	X509_free(cert);
end:
	pr_debug_rm("}");
	return error;
}

static int
print_roa(struct validation *state, char *file, void *arg)
{
	/* TODO */
	handle_roa(file);
	return 0;
}

static int
__handle_manifest(struct validation *state, struct manifest *mft)
{
	struct foreach_args args;
	int error;

	/* Init */
	args.crls = sk_X509_CRL_new_null();
	if (args.crls == NULL) {
		pr_err("Out of memory.");
		return -ENOMEM;
	}

	args.resources = resources_create();
	if (args.resources == NULL) {
		sk_X509_CRL_free(args.crls);
		return -ENOMEM;
	}

	/* Get CRLs as a stack. There will usually only be one. */
	error = foreach_file(state, mft, "crl", pile_crls, args.crls);
	if (error)
		goto end;

	/*
	 * Use CRL stack to validate certificates.
	 * Pile up valid address ranges from the valid certificates.
	 */
	error = foreach_file(state, mft, "cer", pile_addr_ranges, &args);
	if (error)
		goto end;

	/* Use valid address ranges to print ROAs that match them. */
	error = foreach_file(state, mft, "roa", print_roa, &args);

end:
	resources_destroy(args.resources);
	sk_X509_CRL_pop_free(args.crls, X509_CRL_free);
	return error;
}

int
handle_manifest(struct validation *state, char const *file_path)
{
	static OID oid = OID_MANIFEST;
	struct oid_arcs arcs = OID2ARCS(oid);
	struct manifest mft;
	int error;

	mft.file_path = file_path;

	error = signed_object_decode(file_path, &asn_DEF_Manifest, &arcs,
	    (void **) &mft.obj);
	if (error)
		return error;

	error = validate_manifest(mft.obj);
	if (!error)
		error = __handle_manifest(state, &mft);

	ASN_STRUCT_FREE(asn_DEF_Manifest, mft.obj);
	return error;
}
