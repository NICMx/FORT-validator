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
#include "rsync/rsync.h"

/*
 * The X509V3_EXT_METHOD that references NID_sinfo_access uses the AIA item.
 * The SIA's d2i function, therefore, returns AIAs.
 * They are the same as far as LibreSSL is concerned.
 */
typedef AUTHORITY_INFO_ACCESS SIGNATURE_INFO_ACCESS;

struct extension_metadata {
	char *name;
	int nid;
	bool critical;
};

static const struct extension_metadata BC = {
	"Basic Constraints",
	NID_basic_constraints,
	true,
};
static const struct extension_metadata SKI = {
	"Subject Key Identifier",
	NID_subject_key_identifier,
	false,
};
static const struct extension_metadata AKI = {
	"Authority Key Identifier",
	NID_authority_key_identifier,
	false,
};
static const struct extension_metadata KU = {
	"Key Usage",
	NID_key_usage,
	true,
};
static const struct extension_metadata CDP = {
	"CRL Distribution Points",
	NID_crl_distribution_points,
	false,
};
static const struct extension_metadata AIA = {
	"Authority Information Access",
	NID_info_access,
	false,
};
static const struct extension_metadata SIA = {
	"Subject Information Access",
	NID_sinfo_access ,
	false,
};
static const struct extension_metadata CP = {
	"Certificate Policies",
	NID_certificate_policies,
	true,
};
static const struct extension_metadata IR = {
	"IP Resources",
	NID_sbgp_ipAddrBlock,
	true,
};
static const struct extension_metadata AR = {
	"AS Resources",
	NID_sbgp_autonomousSysNum,
	true,
};

struct extension_handler {
	struct extension_metadata const *meta;
	bool mandatory;
	int (*cb)(X509_EXTENSION *, void *);
	void *arg;

	void (*free)(void *);

	/* For internal use */
	bool found;
};

struct sia_arguments {
	X509 *cert;
	STACK_OF(X509_CRL) *crls;
};

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
		goto fail1;

	/* Algorithm Identifier */
	error = oid2arcs(&tal_spki->algorithm.algorithm, &tal_alg_arcs);
	if (error)
		goto fail2;

	if (!ARCS_EQUAL_OIDS(&tal_alg_arcs, oid_rsa)) {
		error = pr_err("TAL's public key format is not RSA PKCS#1 v1.5 with SHA-256.");
		goto fail3;
	}

	/* SPK */
	if (tal_spki->subjectPublicKey.size != cert_spk_len)
		goto fail4;
	if (memcmp(tal_spki->subjectPublicKey.buf, cert_spk, cert_spk_len) != 0)
		goto fail4;

	free_arcs(&tal_alg_arcs);
	ASN_STRUCT_FREE(asn_DEF_SubjectPublicKeyInfo, tal_spki);
	validation_pubkey_valid(state);
	return 0;

fail4:
	error = pr_err("TAL's public key is different than the root certificate's public key.");
fail3:
	free_arcs(&tal_alg_arcs);
fail2:
	ASN_STRUCT_FREE(asn_DEF_SubjectPublicKeyInfo, tal_spki);
fail1:
	validation_pubkey_invalid(state);
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

	/* We'll validate extensions later. */
	return 0;
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

/**
 * Get GENERAL_NAME data.
 */
static int
get_gn(GENERAL_NAME *name, char **guri)
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
	 * URIs.
	 *
	 * Also, nobody seems to be using the other types, and handling them
	 * would be a titanic pain in the ass. So this is what I'm committing
	 * to.
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
	*guri = (char *) ASN1_STRING_get0_data(asn1_string);
	return 0;
}

/*
 * "GENERAL_NAME, global to local"
 * Result has to be freed.
 *
 * If this function returns ENOTRSYNC, it means that @name was not an RSYNC URI.
 * This often should not be treated as an error; please handle gracefully.
 * TODO open call hierarchy.
 */
static int
gn_g2l(GENERAL_NAME *name, char **luri)
{
	char *guri;
	int error;

	error = get_gn(name, &guri);
	if (error)
		return error; /* message already printed. */

	/*
	 * TODO (testers) According to RFC 5280, accessLocation can be an IRI
	 * somehow converted into URI form. I don't think that's an issue
	 * because the RSYNC clone operation should not have performed the
	 * conversion, so we should be looking at precisely the IA5String
	 * directory our g2l version of @asn1_string should contain.
	 * But ask the testers to keep an eye on it anyway.
	 */
	return uri_g2l((char const *) guri, strlen(guri), luri);
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
cannot_decode(struct extension_metadata const *meta)
{
	return pr_err("Extension '%s' seems to be malformed. Cannot decode.",
	    meta->name);
}

static bool
is_rsync(ASN1_IA5STRING *uri)
{
	static char const *const PREFIX = "rsync://";
	size_t prefix_len = strlen(PREFIX);

	return (uri->length >= prefix_len)
	    ? (strncmp((char *) uri->data, PREFIX, strlen(PREFIX)) == 0)
	    : false;
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

	error = get_gn(ad->location, &uri);
	if (error)
		return error;

	pr_debug("caRepository: %s", uri);
	error = download_files(uri);

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

static int
handle_bc(X509_EXTENSION *ext, void *arg)
{
	BASIC_CONSTRAINTS *bc;
	int error;

	bc = X509V3_EXT_d2i(ext);
	if (bc == NULL)
		return cannot_decode(&BC);

	/*
	 * 'The issuer determines whether the "cA" boolean is set.'
	 * ................................. Uh-huh. So nothing then.
	 * Well, libcrypto should do the RFC 5280 thing with it anyway.
	 */

	error = (bc->pathlen == NULL)
	    ? 0
	    : pr_err("%s extension contains a Path Length Constraint.", BC.name);

	BASIC_CONSTRAINTS_free(bc);
	return error;
}

static int
handle_ski(X509_EXTENSION *ext, void *arg)
{
	X509_PUBKEY *pubkey;
	const unsigned char *spk;
	int spk_len;
	int ok;

	/*
	 * "Applications are not required to verify that key identifiers match
	 * when performing certification path validation."
	 * (rfc5280#section-4.2.1.2)
	 * I think "match" refers to the "parent's SKI must match the
	 * children's AKI" requirement, not "The SKI must match the SHA-1 of the
	 * SPK" requirement.
	 * So I guess we're only supposed to check the SHA-1.
	 */

	pubkey = X509_get_X509_PUBKEY((X509 *) arg);
	if (pubkey == NULL) {
		crypto_err("X509_get_X509_PUBKEY() returned NULL");
		return -EINVAL;
	}

	ok = X509_PUBKEY_get0_param(NULL, &spk, &spk_len, NULL, pubkey);
	if (!ok) {
		crypto_err("X509_PUBKEY_get0_param() returned %d", ok);
		return -EINVAL;
	}

	/* Get the SHA-1 of spk */
	/* TODO (certext) ... */

	/* Decode ext */

	/* Compare the SHA and the decoded ext */

	/* Free the decoded ext */

	return 0;
}

static int
handle_ski_ee(X509_EXTENSION *ext, void *arg)
{
	ASN1_OCTET_STRING *ski;
	OCTET_STRING_t *sid = arg;
	int error = 0;

	ski = X509V3_EXT_d2i(ext);
	if (ski == NULL)
		return cannot_decode(&SKI);

	/* rfc6488#section-2.1.6.2 */
	/* rfc6488#section-3.1.c 2/2 */
	if (ski->length != sid->size
	    || memcmp(ski->data, sid->buf, sid->size) != 0) {
		error = pr_err("The EE certificate's subjectKeyIdentifier does not equal the Signed Object's sid.");
	}

	ASN1_OCTET_STRING_free(ski);
	return error;
}

static int
handle_aki_ta(X509_EXTENSION *ext, void *arg)
{
	return 0; /* TODO (certext) implement. */
}

static int
handle_aki(X509_EXTENSION *ext, void *arg)
{
	AUTHORITY_KEYID *aki;
	int error = 0;

	aki = X509V3_EXT_d2i(ext);
	if (aki == NULL)
		return cannot_decode(&AKI);

	if (aki->issuer != NULL) {
		error = pr_err("%s extension contains an authorityCertIssuer.",
		    AKI.name);
		goto end;
	}
	if (aki->serial != NULL) {
		error = pr_err("%s extension contains an authorityCertSerialNumber.",
		    AKI.name);
		goto end;
	}

	/* TODO (certext) stuff */

end:
	AUTHORITY_KEYID_free(aki);
	return error;
}

static int
handle_ku(X509_EXTENSION *ext, unsigned char byte1)
{
	/*
	 * About the key usage string: At time of writing, it's 9 bits long.
	 * But zeroized rightmost bits can be omitted.
	 * This implementation assumes that the ninth bit should always be zero.
	 */

	ASN1_BIT_STRING *ku;
	unsigned char data[2];
	int error = 0;

	ku = X509V3_EXT_d2i(ext);
	if (ku == NULL)
		return cannot_decode(&KU);

	if (ku->length == 0) {
		error = pr_err("%s bit string has no enabled bits.", KU.name);
		goto end;
	}

	memset(data, 0, sizeof(data));
	memcpy(data, ku->data, ku->length);

	if (ku->data[0] != byte1) {
		error = pr_err("Illegal key usage flag string: %u%u%u%u%u%u%u%u%u",
		    !!(ku->data[0] & 0x80), !!(ku->data[0] & 0x40),
		    !!(ku->data[0] & 0x20), !!(ku->data[0] & 0x10),
		    !!(ku->data[0] & 0x08), !!(ku->data[0] & 0x04),
		    !!(ku->data[0] & 0x02), !!(ku->data[0] & 0x01),
		    !!(ku->data[1] & 0x80));
		goto end;
	}

end:
	ASN1_BIT_STRING_free(ku);
	return error;
}

static int
handle_ku_ca(X509_EXTENSION *ext, void *arg)
{
	return handle_ku(ext, 0x06);
}

static int
handle_ku_ee(X509_EXTENSION *ext, void *arg)
{
	return handle_ku(ext, 0x80);
}

static int
handle_cdp(X509_EXTENSION *ext, void *arg)
{
	STACK_OF(DIST_POINT) *crldp = X509V3_EXT_d2i(ext);
	DIST_POINT *dp;
	GENERAL_NAMES *names;
	GENERAL_NAME *name;
	int i;
	int error = 0;
	char *error_msg;

	crldp = X509V3_EXT_d2i(ext);
	if (crldp == NULL)
		return cannot_decode(&CDP);

	if (sk_DIST_POINT_num(crldp) != 1) {
		error = pr_err("The %s extension has %u distribution points. (1 expected)",
		    CDP.name, sk_DIST_POINT_num(crldp));
		goto end;
	}

	dp = sk_DIST_POINT_value(crldp, 0);

	if (dp->CRLissuer != NULL) {
		error_msg = "has a CRLIssuer field";
		goto dist_point_error;
	}
	if (dp->reasons != NULL) {
		error_msg = "has a Reasons field";
		goto dist_point_error;
	}

	if (dp->distpoint == NULL) {
		error_msg = "lacks a distributionPoint field";
		goto dist_point_error;
	}

	/* Bleargh. There's no enum. 0 is fullname, 1 is relativename. */
	switch (dp->distpoint->type) {
	case 0:
		break;
	case 1:
		error_msg = "has a relative name";
		goto dist_point_error;
	default:
		error_msg = "has an unknown type of name";
		goto dist_point_error;
	}

	names = dp->distpoint->name.fullname;
	for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
		name = sk_GENERAL_NAME_value(names, i);
		if (name->type == GEN_URI && is_rsync(name->d.uniformResourceIdentifier)) {
			/*
			 * TODO (certext) check the URI matches what we rsync'd.
			 * Also indent properly.
			 */
			error = 0;
			goto end;
		}
	}

	error_msg = "lacks an RSYNC URI";

dist_point_error:
	error = pr_err("The %s extension's distribution point %s.", CDP.name,
	    error_msg);

end:
	sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
	return error;
}

static int
handle_aia(X509_EXTENSION *ext, void *arg)
{
	AUTHORITY_INFO_ACCESS *aia;
	ACCESS_DESCRIPTION *ad;
	int i;

	aia = X509V3_EXT_d2i(ext);
	if (aia == NULL)
		return cannot_decode(&AIA);

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(aia, i);
		if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers) {
			/*
			 * TODO (certext) check the URI matches what we rsync'd.
			 */
		}
	}

	AUTHORITY_INFO_ACCESS_free(aia);
	return 0;
}

static int
handle_sia_ca(X509_EXTENSION *ext, void *arg)
{
	struct sia_arguments *args = arg;
	struct validation *state;
	SIGNATURE_INFO_ACCESS *sia;
	ACCESS_DESCRIPTION *ad;
	bool rsync_found = false;
	bool manifest_found = false;
	int i;
	int error;

	sia = X509V3_EXT_d2i(ext);
	if (sia == NULL)
		return cannot_decode(&SIA);

	state = state_retrieve();
	if (state == NULL) {
		error = -EINVAL;
		goto end2;
	}
	error = validation_push_cert(state, args->cert, false);
	if (error)
		goto end2;

	/* rsync */
	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(sia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(sia, i);
		if (OBJ_obj2nid(ad->method) == NID_caRepository) {
			error = handle_caRepository(ad);
			if (error == ENOTRSYNC)
				continue;
			if (error)
				goto end1;
			rsync_found = true;
			break;
		}
	}

	if (!rsync_found) {
		pr_err("SIA extension lacks an RSYNC URI caRepository.");
		error = -ESRCH;
		goto end1;
	}

	/* validate */
	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(sia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(sia, i);
		if (OBJ_obj2nid(ad->method) == NID_rpkiManifest) {
			error = handle_rpkiManifest(ad, args->crls);
			if (error)
				goto end1;
			manifest_found = true;
		}
	}

	/* rfc6481#section-2 */
	if (!manifest_found) {
		pr_err("SIA extension lacks an rpkiManifest access description.");
		error = -ESRCH;
	}

end1:
	validation_pop_cert(state); /* Error code is useless. */
end2:
	AUTHORITY_INFO_ACCESS_free(sia);
	return error;
}

static int
handle_sia_ee(X509_EXTENSION *ext, void *arg)
{
	SIGNATURE_INFO_ACCESS *sia;
	ACCESS_DESCRIPTION *ad;
	int i;
	int error = 0;

	sia = X509V3_EXT_d2i(ext);
	if (sia == NULL)
		return cannot_decode(&SIA);

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

static int
handle_cp(X509_EXTENSION *ext, void *arg)
{
	return 0; /* TODO (certext) Implement */
}

static int
handle_ir(X509_EXTENSION *ext, void *arg)
{
	return 0; /* Handled in certificate_get_resources(). */
}

static int
handle_ar(X509_EXTENSION *ext, void *arg)
{
	return 0; /* Handled in certificate_get_resources(). */
}

static int
handle_extension(struct extension_handler *handlers, X509_EXTENSION *ext)
{
	struct extension_handler *handler;
	int nid;

	nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));

	for (handler = handlers; handler->meta != NULL; handler++) {
		if (handler->meta->nid == nid) {
			if (handler->found)
				goto dupe;
			handler->found = true;

			if (handler->meta->critical) {
				if (!X509_EXTENSION_get_critical(ext))
					goto not_critical;
			} else {
				if (X509_EXTENSION_get_critical(ext))
					goto critical;
			}

			return handler->cb(ext, handler->arg);
		}
	}

	if (!X509_EXTENSION_get_critical(ext))
		return 0; /* Unknown and not critical; ignore it. */

	return pr_err("Certificate has unknown extension. (Extension NID: %d)",
	    nid);
dupe:
	return pr_err("Certificate has more than one '%s' extension.",
	    handler->meta->name);
not_critical:
	return pr_err("Extension '%s' is supposed to be marked critical.",
	    handler->meta->name);
critical:
	return pr_err("Extension '%s' is not supposed to be marked critical.",
	    handler->meta->name);
}

static int
handle_cert_extensions(struct extension_handler *handlers, X509 *cert)
{
	struct extension_handler *handler;
	int e;
	int error;

	for (e = 0; e < X509_get_ext_count(cert); e++) {
		error = handle_extension(handlers, X509_get_ext(cert, e));
		if (error)
			return error;
	}

	for (handler = handlers; handler->meta != NULL; handler++) {
		if (handler->mandatory && !handler->found)
			return pr_err("Certificate is missing the '%s' extension.",
			    handler->meta->name);
	}

	return 0;
}

int
certificate_traverse_ta(X509 *cert, STACK_OF(X509_CRL) *crls)
{
	struct sia_arguments sia_args;
	struct extension_handler handlers[] = {
	   /* ext   reqd   handler        arg       */
	    { &BC,  true,  handle_bc,               },
	    { &SKI, true,  handle_ski,     cert     },
	    { &AKI, false, handle_aki_ta,           },
	    { &KU,  true,  handle_ku_ca,            },
	    { &SIA, true,  handle_sia_ca, &sia_args },
	    { &CP,  true,  handle_cp,               },
	    { &IR,  false, handle_ir,               },
	    { &AR,  false, handle_ar,               },
	    { NULL },
	};

	sia_args.cert = cert;
	sia_args.crls = crls;

	return handle_cert_extensions(handlers, cert);
}

int
certificate_traverse_ca(X509 *cert, STACK_OF(X509_CRL) *crls)
{
	struct sia_arguments sia_args;
	struct extension_handler handlers[] = {
	   /* ext   reqd   handler        arg       */
	    { &BC,  true,  handle_bc,            },
	    { &SKI, true,  handle_ski,     cert     },
	    { &AKI, true,  handle_aki,              },
	    { &KU,  true,  handle_ku_ca,            },
	    { &CDP, true,  handle_cdp,              },
	    { &AIA, true,  handle_aia,              },
	    { &SIA, true,  handle_sia_ca, &sia_args },
	    { &CP,  true,  handle_cp,               },
	    { &IR,  false, handle_ir,               },
	    { &AR,  false, handle_ar,               },
	    { NULL },
	};

	sia_args.cert = cert;
	sia_args.crls = crls;

	return handle_cert_extensions(handlers, cert);
}

int
certificate_traverse_ee(X509 *cert, OCTET_STRING_t *sid)
{
	struct extension_handler handlers[] = {
	   /* ext   reqd   handler        arg */
	    { &SKI, true,  handle_ski_ee, sid },
	    { &AKI, true,  handle_aki,        },
	    { &KU,  true,  handle_ku_ee,      },
	    { &CDP, true,  handle_cdp,        },
	    { &AIA, true,  handle_aia,        },
	    { &SIA, true,  handle_sia_ee,     },
	    { &CP,  true,  handle_cp,         },
	    { &IR,  false, handle_ir,         },
	    { &AR,  false, handle_ar,         },
	    { NULL },
	};

	return handle_cert_extensions(handlers, cert);
}
