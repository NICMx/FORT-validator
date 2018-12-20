#include "certificate.h"

#include <errno.h>
#include <libcmscodec/SubjectInfoAccessSyntax.h>
#include <libcmscodec/SubjectPublicKeyInfo.h>
#include <libcmscodec/IPAddrBlocks.h>

#include "common.h"
#include "log.h"
#include "manifest.h"
#include "thread_var.h"
#include "asn1/decode.h"
#include "asn1/oid.h"

/*
 * The X509V3_EXT_METHOD that references NID_sinfo_access uses the AIA item.
 * The SIA's d2i function, therefore, returns AIAs.
 * They are the same as far as LibreSSL is concerned.
 */
typedef AUTHORITY_INFO_ACCESS SIGNATURE_INFO_ACCESS;

bool is_certificate(char const *file_name)
{
	return file_has_extension(file_name, strlen(file_name), ".cer");
}

static int
validate_serial_number(X509 *cert)
{
	/* TODO (field) implement this properly. */

	BIGNUM *number;

	number = ASN1_INTEGER_to_BN(X509_get0_serialNumber(cert), NULL);
	if (number == NULL) {
		crypto_err("Could not parse certificate serial number");
		return 0;
	}

	pr_debug_prefix();
	fprintf(stdout, "serial Number: ");
	BN_print_fp(stdout, number);
	fprintf(stdout, "\n");
	BN_free(number);

	return 0;
}

static int
validate_signature_algorithm(X509 *cert)
{
	int nid;

	nid = OBJ_obj2nid(X509_get0_tbs_sigalg(cert)->algorithm);
	if (nid != NID_sha256WithRSAEncryption)
		return pr_err("Certificate's Signature Algorithm is not RSASSA-PKCS1-v1_5.");

	return 0;
}

static int
validate_name(X509_NAME *name, char *what)
{
#ifdef DEBUG
	char *str;
#endif
	int str_len;

	str_len = X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0);
	if (str_len < 0) {
		pr_err("Certificate's %s lacks the CommonName atribute.", what);
		return -ESRCH;
	}

#ifdef DEBUG
	str = calloc(str_len + 1, 1);
	if (str == NULL) {
		pr_err("Out of memory.");
		return -ENOMEM;
	}

	X509_NAME_get_text_by_NID(name, NID_commonName, str, str_len + 1);

	pr_debug("%s: %s", what, str);
	free(str);
#endif

	return 0;
}

static int
validate_spki(const unsigned char *cert_spk, int cert_spk_len)
{
	struct validation *state;
	struct tal *tal;

	struct SubjectPublicKeyInfo *tal_spki;
	unsigned char const *_tal_spki;
	size_t _tal_spki_len;

	static const OID oid_rsa = OID_RSA;
	struct oid_arcs tal_alg_arcs;

	int error;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	tal = validation_tal(state);
	if (tal == NULL)
		return pr_crit("Validation state has no TAL.");

	/*
	 * We have a problem at this point:
	 *
	 * RFC 7730 says "The public key used to verify the trust anchor MUST be
	 * the same as the subjectPublicKeyInfo in the CA certificate and in the
	 * TAL."
	 *
	 * It seems that libcrypto decodes the Subject Public Key Info (SPKI)
	 * and gives us the Subject Public Key (SPK) instead. So we can't just
	 * compare the two keys just like that.
	 *
	 * Luckily, the only other component of the SPKI is the algorithm
	 * identifier. So doing a field-by-field comparison is not too much
	 * trouble. We'll have to decode the TAL's SPKI though.
	 */

	tal_get_spki(tal, &_tal_spki, &_tal_spki_len);
	error = asn1_decode(_tal_spki, _tal_spki_len,
	    &asn_DEF_SubjectPublicKeyInfo, (void **) &tal_spki);
	if (error)
		return error;

	/* Algorithm Identifier */
	error = oid2arcs(&tal_spki->algorithm.algorithm, &tal_alg_arcs);
	if (error)
		goto fail;

	if (!ARCS_EQUAL_OIDS(&tal_alg_arcs, oid_rsa)) {
		error = pr_err("TAL's public key format is not RSA PKCS#1 v1.5 with SHA-256.");
		goto fail;
	}

	/* SPK */
	if (tal_spki->subjectPublicKey.size != cert_spk_len)
		goto not_equal;
	if (memcmp(tal_spki->subjectPublicKey.buf, cert_spk, cert_spk_len) != 0)
		goto not_equal;

	ASN_STRUCT_FREE(asn_DEF_SubjectPublicKeyInfo, tal_spki);
	return 0;

not_equal:
	error = pr_err("TAL's public key is different than the root certificate's public key.");
fail:
	ASN_STRUCT_FREE(asn_DEF_SubjectPublicKeyInfo, tal_spki);
	return error;
}

static int
validate_public_key(X509 *cert, bool is_root)
{
	X509_PUBKEY *pubkey;
	ASN1_OBJECT *alg;
	int alg_nid;
	const unsigned char *bytes;
	int bytes_len;
	int ok;
	int error;

	pubkey = X509_get_X509_PUBKEY(cert);
	if (pubkey == NULL) {
		crypto_err("X509_get_X509_PUBKEY() returned NULL");
		return -EINVAL;
	}

	ok = X509_PUBKEY_get0_param(&alg, &bytes, &bytes_len, NULL, pubkey);
	if (!ok) {
		crypto_err("X509_PUBKEY_get0_param() returned %d", ok);
		return -EINVAL;
	}

	alg_nid = OBJ_obj2nid(alg);
	/*
	 * TODO Everyone uses this algorithm, but at a quick glance, it doesn't
	 * seem to match RFC 7935's public key algorithm. Wtf?
	 */
	if (alg_nid != NID_rsaEncryption) {
		return pr_err("Certificate's public key format is %d, not RSA PKCS#1 v1.5 with SHA-256.",
		    alg_nid);
	}

	/*
	 * BTW: WTF. About that algorithm:
	 *
	 * RFC 6485: "The value for the associated parameters from that clause
	 * [RFC4055] MUST also be used for the parameters field."
	 * RFC 4055: "Implementations MUST accept the parameters being absent as
	 * well as present."
	 *
	 * Either the RFCs found a convoluted way of saying nothing, or I'm not
	 * getting the message.
	 */

	if (is_root) {
		error = validate_spki(bytes, bytes_len);
		if (error)
			return error;
	}

	return 0;
}

static int
validate_extensions(X509 *cert)
{
	/* TODO (field) */
	return 0;
}

int
certificate_validate_rfc6487(X509 *cert, bool is_root)
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
	if (X509_get_version(cert) != 2)
		return pr_err("Certificate version is not v3.");

	/* rfc6487#section-4.2 */
	error = validate_serial_number(cert);
	if (error)
		return error;

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
	 * TODO (field) "Each distinct subordinate CA and
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
	/* Fragment of rfc7730#section-2.2 */
	error = validate_public_key(cert, is_root);
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
		goto end;
	}

	cert = d2i_X509_bio(bio, NULL);
	if (cert == NULL) {
		error = crypto_err("Error parsing certificate");
		goto end;
	}

	*result = cert;
	error = 0;
end:
	BIO_free(bio);
	return error;
}

int
certificate_validate_chain(X509 *cert, STACK_OF(X509_CRL) *crls)
{
	/* Reference: openbsd/src/usr.bin/openssl/verify.c */

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
	if (crls != NULL)
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
	ASN1_STRING *asn1_string;
	int type;

	asn1_string = GENERAL_NAME_get0_value(name, &type);

	/*
	 * RFC 6487: "This extension MUST have an instance of an
	 * AccessDescription with an accessMethod of id-ad-rpkiManifest, (...)
	 * with an rsync URI [RFC5781] form of accessLocation."
	 *
	 * Ehhhhhh. It's a little annoying in that it seems to be stucking more
	 * than one requirement in a single sentence, which I think is rather
	 * rare for an RFC. Normally they tend to hammer things more.
	 *
	 * Does it imply that the GeneralName CHOICE is constrained to type
	 * "uniformResourceIdentifier"? I guess so, though I don't see anything
	 * stopping a few of the other types from also being capable of storing
	 * URIs. Then again, DER is all about unique serialized representation.
	 *
	 * Also, nobody seems to be using the other types, and handling them
	 * would be a titanic pain in the ass. So this is what I'm committing
	 * to.
	 *
	 * I know that this is the logical conclusion; it's just that I know
	 * that at some point in the future I'm going find myself bewilderingly
	 * staring at this if again.
	 */
	if (type != GEN_URI) {
		pr_err("Unknown GENERAL_NAME type: %d", type);
		return -ENOTSUPPORTED;
	}

	/*
	 * GEN_URI signals an IA5String.
	 * IA5String is a subset of ASCII, so this cast is safe.
	 * No guarantees of a NULL chara, though.
	 *
	 * TODO (testers) According to RFC 5280, accessLocation can be an IRI
	 * somehow converted into URI form. I don't think that's an issue
	 * because the RSYNC clone operation should not have performed the
	 * conversion, so we should be looking at precisely the IA5String
	 * directory our g2l version of @asn1_string should contain.
	 * But ask the testers to keep an eye on it anyway.
	 */
	return uri_g2l((char const *) ASN1_STRING_get0_data(asn1_string),
	    ASN1_STRING_length(asn1_string), luri);
}

static int
handle_ip_extension(X509_EXTENSION *ext, struct resources *resources)
{
	ASN1_OCTET_STRING *string;
	struct IPAddrBlocks *blocks;
	OCTET_STRING_t *family;
	int i;
	int error;

	string = X509_EXTENSION_get_data(ext);
	error = asn1_decode(string->data, string->length, &asn_DEF_IPAddrBlocks,
	    (void **) &blocks);
	if (error)
		return error;

	/*
	 * rfc3779#section-2.2.3.3, rfc6487#section-4.8.10:
	 * We're expecting either one element (IPv4 or IPv6) or two elements
	 * (IPv4 then IPv6).
	 */
	switch (blocks->list.count) {
	case 1:
		break;
	case 2:
		family = &blocks->list.array[0]->addressFamily;
		if (get_addr_family(family) != AF_INET) {
			error = pr_err("First IP address block listed is not v4.");
			goto end;
		}
		family = &blocks->list.array[1]->addressFamily;
		if (get_addr_family(family) != AF_INET6) {
			error = pr_err("Second IP address block listed is not v6.");
			goto end;
		}
		break;
	default:
		error = pr_err("Got %d IP address blocks Expected; 1 or 2 expected.",
		    blocks->list.count);
		goto end;
	}

	for (i = 0; i < blocks->list.count && !error; i++)
		error = resources_add_ip(resources, blocks->list.array[i]);

end:
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
	int error;
	bool ip_ext_found = false;
	bool asn_ext_found = false;

	/* Reference: X509_get_ext_d2i */
	/* rfc6487#section-2 */

	for (i = 0; i < X509_get_ext_count(cert); i++) {
		ext = X509_get_ext(cert, i);

		switch (OBJ_obj2nid(X509_EXTENSION_get_object(ext))) {
		case NID_sbgp_ipAddrBlock:
			if (ip_ext_found)
				return pr_err("Multiple IP extensions found.");
			if (!X509_EXTENSION_get_critical(ext))
				return pr_err("The IP extension is not marked as critical.");

			pr_debug_add("IP {");
			error = handle_ip_extension(ext, resources);
			pr_debug_rm("}");
			ip_ext_found = true;

			if (error)
				return error;
			break;

		case NID_sbgp_autonomousSysNum:
			if (asn_ext_found)
				return pr_err("Multiple AS extensions found.");
			if (!X509_EXTENSION_get_critical(ext))
				return pr_err("The AS extension is not marked as critical.");

			pr_debug_add("ASN {");
			error = handle_asn_extension(ext, resources);
			pr_debug_rm("}");
			asn_ext_found = true;

			if (error)
				return error;
			break;
		}
	}

	if (!ip_ext_found && !asn_ext_found)
		return pr_err("Certificate lacks both IP and AS extension.");

	return 0;
}

static int
handle_rpkiManifest(ACCESS_DESCRIPTION *ad, STACK_OF(X509_CRL) *crls)
{
	char *uri;
	int error;

	error = gn_g2l(ad->location, &uri);
	if (error)
		return error;

	error = handle_manifest(uri, crls);

	free(uri);
	return error;
}

static int
handle_caRepository(ACCESS_DESCRIPTION *ad)
{
	char *uri;
	int error;

	error = gn_g2l(ad->location, &uri);
	if (error)
		return error;

	pr_debug("caRepository: %s", uri);

	free(uri);
	return error;
}

static int
handle_signedObject(ACCESS_DESCRIPTION *ad)
{
	char *uri;
	int error;

	error = gn_g2l(ad->location, &uri);
	if (error)
		return error;

	pr_debug("signedObject: %s", uri);

	free(uri);
	return error;
}

int
certificate_traverse_ca(X509 *cert, STACK_OF(X509_CRL) *crls)
{
	struct validation *state;
	SIGNATURE_INFO_ACCESS *sia;
	ACCESS_DESCRIPTION *ad;
	bool manifest_found = false;
	int nid;
	int i;
	int error;

	sia = X509_get_ext_d2i(cert, NID_sinfo_access, NULL, NULL);
	if (sia == NULL) {
		pr_err("Certificate lacks a Subject Information Access extension.");
		return -ESRCH;
	}

	state = state_retrieve();
	if (state == NULL) {
		error = -EINVAL;
		goto end2;
	}
	error = validation_push_cert(state, cert);
	if (error)
		goto end2;

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(sia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(sia, i);
		nid = OBJ_obj2nid(ad->method);

		if (nid == NID_rpkiManifest) {
			error = handle_rpkiManifest(ad, crls);
			if (error)
				goto end1;
			manifest_found = true;

		} else if (nid == NID_caRepository) {
			error = handle_caRepository(ad);
			if (error)
				goto end1;
		}
	}

	/* rfc6481#section-2 */
	if (!manifest_found) {
		pr_err("Repository publication point seems to have no manifest.");
		error = -ESRCH;
	}

end1:
	validation_pop_cert(state); /* Error code is useless. */
end2:
	AUTHORITY_INFO_ACCESS_free(sia);
	return error;
}

int
certificate_traverse_ee(X509 *cert)
{
	SIGNATURE_INFO_ACCESS *sia;
	ACCESS_DESCRIPTION *ad;
	int i;
	int error;

	sia = X509_get_ext_d2i(cert, NID_sinfo_access, NULL, NULL);
	if (sia == NULL) {
		pr_err("Certificate lacks a Subject Information Access extension.");
		return -ESRCH;
	}

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(sia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(sia, i);
		if (OBJ_obj2nid(ad->method) == NID_signedObject) {
			error = handle_signedObject(ad);
			if (error)
				goto end;

		} else {
			/* rfc6487#section-4.8.8.2 */
			error = pr_err("EE Certificate has an non-signedObject access description.");
			goto end;
		}
	}

end:
	AUTHORITY_INFO_ACCESS_free(sia);
	return error;
}
