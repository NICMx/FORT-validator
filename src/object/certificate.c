#include "certificate.h"

#include <libcmscodec/SubjectInfoAccessSyntax.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <libcmscodec/ASIdentifiers.h>
#include <libcmscodec/IPAddrBlocks.h>

#include "common.h"
#include "log.h"
#include "manifest.h"
#include "asn1/decode.h"

/*
 * The X509V3_EXT_METHOD that references NID_sinfo_access uses the AIA item.
 * The SIA's d2i function, therefore, returns AIAs.
 * They are the same as far as LibreSSL is concerned.
 */
typedef AUTHORITY_INFO_ACCESS SIGNATURE_INFO_ACCESS;

bool is_certificate(char const *file_name)
{
	return file_has_extension(file_name, "cer");
}

int
certificate_load(struct validation *state, const char *file, X509 **result)
{
	X509 *cert = NULL;
	BIO *bio;
	int error;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL)
		return crypto_err(state, "BIO_new(BIO_s_file()) returned NULL");
	if (BIO_read_filename(bio, file) <= 0) {
		error = crypto_err(state, "Error reading certificate '%s'", file);
		goto end;
	}

	cert = d2i_X509_bio(bio, NULL);
	if (cert == NULL) {
		error = crypto_err(state, "Error parsing certificate '%s'", file);
		goto end;
	}

	*result = cert;
	error = 0;

end:
	BIO_free(bio);
	return error;
}

int
certificate_validate(struct validation *state, X509 *cert,
    STACK_OF(X509_CRL) *crls)
{
	/*
	 * TODO
	 * The only difference between -CAfile and -trusted, as it seems, is
	 * that -CAfile consults the default file location, while -trusted does
	 * not. As far as I can tell, this means that we absolutely need to use
	 * -trusted.
	 * So, just in case, enable -no-CAfile and -no-CApath.
	 */

	X509_STORE_CTX *ctx;
	int ok;
	int error;

	ctx = X509_STORE_CTX_new();
	if (ctx == NULL) {
		crypto_err(state, "X509_STORE_CTX_new() returned NULL");
		return -EINVAL;
	}

	/* Returns 0 or 1 , all callers test ! only. */
	ok = X509_STORE_CTX_init(ctx, validation_store(state), cert, NULL);
	if (!ok) {
		crypto_err(state, "X509_STORE_CTX_init() returned %d", ok);
		goto abort;
	}

	X509_STORE_CTX_trusted_stack(ctx, validation_certs(state));
	X509_STORE_CTX_set0_crls(ctx, crls);

	/*
	 * HERE'S THE MEAT OF LIBCRYPTO'S VALIDATION.
	 *
	 * Can return negative codes, all callers do <= 0.
	 *
	 * Debugging BTW: If you're looking for ctx->verify,
	 * it might be internal_verify() from x509_vfy.c.
	 */
	ok = X509_verify_cert(ctx);
	if (ok <= 0) {
		/*
		 * ARRRRGGGGGGGGGGGGG
		 * Do not use crypto_err() here; for some reason the proper
		 * error code is stored in the context.
		 */
		error = X509_STORE_CTX_get_error(ctx);
		if (error) {
			pr_err("Certificate validation failed: %s",
			    X509_verify_cert_error_string(error));
		} else {
			/*
			 * ...But don't trust X509_STORE_CTX_get_error() either.
			 * That said, there's not much to do about !error,
			 * so hope for the best.
			 */
			crypto_err(state, "Certificate validation failed: %d",
			    ok);
		}

		goto abort;
	}

	X509_STORE_CTX_free(ctx);
	return 0;

abort:
	X509_STORE_CTX_free(ctx);
	return -EINVAL;
}

/*
 * "GENERAL_NAME, global to local"
 * Result has to be freed.
 */
static int
gn_g2l(GENERAL_NAME *name, char **luri)
{
	char const *uri;
	int error;

	error = gn2uri(name, &uri);
	if (error)
		return error;

	return uri_g2l(uri, luri);
}

static int
handle_ip_extension(struct validation *state, X509_EXTENSION *ext,
    struct resources *resources)
{
	ASN1_OCTET_STRING *string;
	struct IPAddrBlocks *blocks;
	int i;
	int error;

	string = X509_EXTENSION_get_data(ext);
	error = asn1_decode(string->data, string->length, &asn_DEF_IPAddrBlocks,
	    (void **) &blocks);
	if (error)
		return error;

	/*
	 * TODO There MUST be only one IPAddressFamily SEQUENCE per AFI.
	 * Each SEQUENCE MUST be ordered by ascending addressFamily values.
	 */
	for (i = 0; i < blocks->list.count; i++) {
		error = resources_add_ip(resources, blocks->list.array[i],
		    validation_peek_resource(state));
		if (error)
			break;
	}

	ASN_STRUCT_FREE(asn_DEF_IPAddrBlocks, blocks);
	return error;
}

static int
handle_asn_extension(struct validation *state, X509_EXTENSION *ext,
    struct resources *resources)
{
	ASN1_OCTET_STRING *string;
	struct ASIdentifiers *ids;
	int error;

	string = X509_EXTENSION_get_data(ext);
	error = asn1_decode(string->data, string->length,
	    &asn_DEF_ASIdentifiers, (void **) &ids);
	if (error)
		return error;

	error = resources_add_asn(resources, ids,
	    validation_peek_resource(state));

	ASN_STRUCT_FREE(asn_DEF_ASIdentifiers, ids);
	return error;
}

int
certificate_get_resources(struct validation *state, X509 *cert,
    struct resources *resources)
{
	X509_EXTENSION *ext;
	int i;
	int error = 0;

	/* Reference: X509_get_ext_d2i */
	/* TODO ensure that each extension can only be found once. */

	for (i = 0; i < X509_get_ext_count(cert); i++) {
		ext = X509_get_ext(cert, i);

		switch (OBJ_obj2nid(X509_EXTENSION_get_object(ext))) {
		case NID_sbgp_ipAddrBlock:
			pr_debug_add("IP {");
			error = handle_ip_extension(state, ext, resources);
			pr_debug_rm("}");
			break;
		case NID_sbgp_autonomousSysNum:
			pr_debug_add("ASN {");
			error = handle_asn_extension(state, ext, resources);
			pr_debug_rm("}");
			break;
		}

		if (error)
			return error;
	}

	return error;
}

int certificate_traverse(struct validation *state, X509 *cert)
{
	SIGNATURE_INFO_ACCESS *sia;
	ACCESS_DESCRIPTION *ad;
	char *uri;
	int i;
	int error;

	sia = X509_get_ext_d2i(cert, NID_sinfo_access, NULL, NULL);
	if (sia == NULL) {
		pr_err("Certificate lacks a Subject Information Access extension.");
		return -ESRCH;
	}

	error = 0;
	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(sia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(sia, i);

		if (OBJ_obj2nid(ad->method) == NID_rpkiManifest) {
			error = gn_g2l(ad->location, &uri);
			if (error)
				goto end;
			error = handle_manifest(state, uri);
			free(uri);
			if (error)
				goto end;
		}
	}

end:
	AUTHORITY_INFO_ACCESS_free(sia);
	return error;
}
