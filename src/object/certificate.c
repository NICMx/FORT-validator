#include "certificate.h"

#include <errno.h>
#include <libcmscodec/SubjectInfoAccessSyntax.h>
#include <libcmscodec/IPAddrBlocks.h>

#include "common.h"
#include "log.h"
#include "manifest.h"
#include "thread_var.h"
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

static int
validate_signature_algorithm(X509 *cert)
{
	int nid;

	nid = OBJ_obj2nid(X509_get0_tbs_sigalg(cert)->algorithm);
	if (nid != NID_sha256WithRSAEncryption) {
		pr_err("Certificate's Signature Algorithm is not RSASSA-PKCS1-v1_5.");
		return -EINVAL;
	}

	return 0;
}

static int
validate_name(X509_NAME *name, char *what)
{
	X509_NAME_ENTRY *entry;
	int nid;
	int i;

	for (i = 0; i < X509_NAME_entry_count(name); i++) {
		entry = X509_NAME_get_entry(name, i);
		nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));
		if (nid == NID_commonName)
			return 0;
	}

	pr_err("Certificate's %s lacks the CommonName atribute.", what);
	return -ESRCH;
}

static int
validate_public_key(X509 *cert)
{
	X509_PUBKEY *pubkey;
	ASN1_OBJECT *algorithm;
	int nid;
	int ok;

	pubkey = X509_get_X509_PUBKEY(cert);
	if (pubkey == NULL) {
		crypto_err("X509_get_X509_PUBKEY() returned NULL.");
		return -EINVAL;
	}

	ok = X509_PUBKEY_get0_param(&algorithm, NULL, NULL, NULL, pubkey);
	if (!ok) {
		crypto_err("X509_PUBKEY_get0_param() returned %d.", ok);
		return -EINVAL;
	}

	nid = OBJ_obj2nid(algorithm);
	/*
	 * TODO Everyone uses this algorithm, but at a quick glance, it doesn't
	 * seem to match RFC 7935's public key algorithm. Wtf?
	 */
	if (nid != NID_rsaEncryption) {
		pr_err("Certificate's public key format is %d, not RSA PKCS#1 v1.5 with SHA-256.",
		    nid);
		return -EINVAL;
	}

	/*
	 * BTW: WTF.
	 *
	 * RFC 6485: "The value for the associated parameters from that clause
	 * [RFC4055] MUST also be used for the parameters field."
	 * RFC 4055: "Implementations MUST accept the parameters being absent as
	 * well as present."
	 *
	 * Either the RFCs found a convoluted way of saying nothing, or I'm not
	 * getting the message.
	 */

	return 0;
}

static int
validate_extensions(X509 *cert)
{
	/* TODO */
	return 0;
}

static int
rfc6487_validate(X509 *cert)
{
	int error;

	/*
	 * I'm simply assuming that libcrypto implements RFC 5280. (I mean, it's
	 * not really stated anywhere AFAIK, but since OpenSSL is supposedly the
	 * quintessential crypto lib implementation, and RFC 5280 is supposedly
	 * the generic certificate RFC, it's fair to say it does a well enough
	 * job for all practical purposes.)
	 *
	 * But it's obvious that we can't assume that LibreSSL implements RFC
	 * 6487. It clearly doesn't.
	 *
	 * So here we go.
	 */

	/* rfc6487#section-4.1 */
	if (X509_get_version(cert) != 2) {
		pr_err("Certificate version is not v3.");
		return -EINVAL;
	}

	/* TODO rfc6487#section-4.2 */

	/* rfc6487#section-4.3 */
	error = validate_signature_algorithm(cert);
	if (error)
		return error;

	/* rfc6487#section-4.4 */
	error = validate_name(X509_get_issuer_name(cert), "issuer");
	if (error)
		return error;

	/*
	 * rfc6487#section-4.5
	 *
	 * TODO "Each distinct subordinate CA and
	 * EE certified by the issuer MUST be identified using a subject name
	 * that is unique per issuer.  In this context, "distinct" is defined as
	 * an entity and a given public key."
	 */
	error = validate_name(X509_get_subject_name(cert), "subject");
	if (error)
		return error;

	/* rfc6487#section-4.6 */
	/* libcrypto already does this. */

	/* rfc6487#section-4.7 */
	error = validate_public_key(cert);
	if (error)
		return error;

	return validate_extensions(cert);
}

int
certificate_load(const char *file, X509 **result)
{
	X509 *cert = NULL;
	BIO *bio;
	int error;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL)
		return crypto_err("BIO_new(BIO_s_file()) returned NULL");
	if (BIO_read_filename(bio, file) <= 0) {
		error = crypto_err("Error reading certificate");
		goto abort1;
	}

	cert = d2i_X509_bio(bio, NULL);
	if (cert == NULL) {
		error = crypto_err("Error parsing certificate");
		goto abort1;
	}

	error = rfc6487_validate(cert);
	if (error)
		goto abort2;

	*result = cert;
	BIO_free(bio);
	return 0;

abort2:
	X509_free(cert);
abort1:
	BIO_free(bio);
	return error;
}

int
certificate_validate(X509 *cert, STACK_OF(X509_CRL) *crls)
{
	/*
	 * TODO
	 * The only difference between -CAfile and -trusted, as it seems, is
	 * that -CAfile consults the default file location, while -trusted does
	 * not. As far as I can tell, this means that we absolutely need to use
	 * -trusted.
	 * So, just in case, enable -no-CAfile and -no-CApath.
	 */

	struct validation *state;
	X509_STORE_CTX *ctx;
	int ok;
	int error;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	ctx = X509_STORE_CTX_new();
	if (ctx == NULL) {
		crypto_err("X509_STORE_CTX_new() returned NULL");
		return -EINVAL;
	}

	/* Returns 0 or 1 , all callers test ! only. */
	ok = X509_STORE_CTX_init(ctx, validation_store(state), cert, NULL);
	if (!ok) {
		crypto_err("X509_STORE_CTX_init() returned %d", ok);
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
			crypto_err("Certificate validation failed: %d", ok);
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
handle_ip_extension(X509_EXTENSION *ext, struct resources *resources)
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
		error = resources_add_ip(resources, blocks->list.array[i]);
		if (error)
			break;
	}

	ASN_STRUCT_FREE(asn_DEF_IPAddrBlocks, blocks);
	return error;
}

static int
handle_asn_extension(X509_EXTENSION *ext, struct resources *resources)
{
	ASN1_OCTET_STRING *string;
	struct ASIdentifiers *ids;
	int error;

	string = X509_EXTENSION_get_data(ext);
	error = asn1_decode(string->data, string->length,
	    &asn_DEF_ASIdentifiers, (void **) &ids);
	if (error)
		return error;

	error = resources_add_asn(resources, ids);

	ASN_STRUCT_FREE(asn_DEF_ASIdentifiers, ids);
	return error;
}

int
certificate_get_resources(X509 *cert, struct resources *resources)
{
	X509_EXTENSION *ext;
	int i;
	int error = 0;

	/* Reference: X509_get_ext_d2i */
	/*
	 * TODO ensure that each extension can only be found once.
	 * TODO rfc6487#section-2 also ensure that at least one IP or ASN
	 * extension is found.
	 * TODO rfc6487#section-2 ensure that the IP/ASN extensions are
	 * critical.
	 */

	for (i = 0; i < X509_get_ext_count(cert); i++) {
		ext = X509_get_ext(cert, i);

		switch (OBJ_obj2nid(X509_EXTENSION_get_object(ext))) {
		case NID_sbgp_ipAddrBlock:
			pr_debug_add("IP {");
			error = handle_ip_extension(ext, resources);
			pr_debug_rm("}");
			break;
		case NID_sbgp_autonomousSysNum:
			pr_debug_add("ASN {");
			error = handle_asn_extension(ext, resources);
			pr_debug_rm("}");
			break;
		}

		if (error)
			return error;
	}

	return error;
}

int certificate_traverse(X509 *cert)
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
			error = handle_manifest(uri);
			free(uri);
			if (error)
				goto end;
		}
	}

end:
	AUTHORITY_INFO_ACCESS_free(sia);
	return error;
}
