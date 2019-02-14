#include "certificate.h"

#include <errno.h>
#include <stdint.h> /* SIZE_MAX */
#include <libcmscodec/SubjectPublicKeyInfo.h>
#include <libcmscodec/IPAddrBlocks.h>

#include "algorithm.h"
#include "common.h"
#include "config.h"
#include "extension.h"
#include "log.h"
#include "manifest.h"
#include "nid.h"
#include "thread_var.h"
#include "asn1/decode.h"
#include "asn1/oid.h"
#include "crypto/hash.h"
#include "rsync/rsync.h"

/* Just to prevent some line breaking. */
#define GN_URI uniformResourceIdentifier

/*
 * The X509V3_EXT_METHOD that references NID_sinfo_access uses the AIA item.
 * The SIA's d2i function, therefore, returns AIAs.
 * They are the same as far as LibreSSL is concerned.
 */
typedef AUTHORITY_INFO_ACCESS SIGNATURE_INFO_ACCESS;

struct ski_arguments {
	X509 *cert;
	OCTET_STRING_t *sid;
};

static int
validate_serial_number(X509 *cert)
{
	struct validation *state;
	BIGNUM *number;
	int error;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	number = ASN1_INTEGER_to_BN(X509_get0_serialNumber(cert), NULL);
	if (number == NULL)
		return crypto_err("Could not parse certificate serial number");

#ifdef DEBUG
	pr_debug_prefix();
	fprintf(stdout, "serial Number: ");
	BN_print_fp(stdout, number);
	fprintf(stdout, "\n");
#endif

	error = validation_store_serial_number(state, number);
	if (error)
		BN_free(number);

	return error;
}

static int
validate_signature_algorithm(X509 *cert)
{
	int nid;

	nid = OBJ_obj2nid(X509_get0_tbs_sigalg(cert)->algorithm);
	if (nid != rpki_signature_algorithm())
		return pr_err("Certificate's Signature Algorithm is not RSASSA-PKCS1-v1_5.");

	return 0;
}

static int
validate_issuer(X509 *cert, bool is_ta)
{
	X509_NAME *issuer;
	int error;

	issuer = X509_get_issuer_name(cert);

	if (!is_ta)
		return validate_issuer_name("Certificate", issuer);

	error = x509_name_decode(issuer, NID_commonName, NULL);
	if (error == -ESRCH)
		pr_err("The 'issuer' name lacks a commonName attribute.");

	return error;
}

static int
validate_subject(X509 *cert)
{
	struct validation *state;
	char *subject;
	int error;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	error = x509_name_decode(X509_get_subject_name(cert), NID_commonName,
	    &subject);
	if (error == -ESRCH)
		pr_err("Certificate's subject lacks the CommonName atribute.");
	if (error)
		return error;

	error = validation_store_subject(state, subject);

	free(subject);
	return error;
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

	fnstack_push(tal_get_file_name(tal));
	tal_get_spki(tal, &_tal_spki, &_tal_spki_len);
	error = asn1_decode(_tal_spki, _tal_spki_len,
	    &asn_DEF_SubjectPublicKeyInfo, (void **) &tal_spki);
	fnstack_pop();

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
	if (pubkey == NULL)
		return crypto_err("X509_get_X509_PUBKEY() returned NULL");

	ok = X509_PUBKEY_get0_param(&alg, &bytes, &bytes_len, NULL, pubkey);
	if (!ok)
		return crypto_err("X509_PUBKEY_get0_param() returned %d", ok);

	alg_nid = OBJ_obj2nid(alg);
	if (alg_nid != rpki_public_key_algorithm()) {
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
	error = validate_issuer(cert, is_root);
	if (error)
		return error;

	/*
	 * rfc6487#section-4.5
	 *
	 * "An issuer SHOULD use a different subject name if the subject's
	 * key pair has changed" (it's a SHOULD, so [for now] avoid validation)
	 */
	error = validate_subject(cert);
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
certificate_load(struct rpki_uri const *uri, X509 **result)
{
	X509 *cert = NULL;
	BIO *bio;
	int error;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL)
		return crypto_err("BIO_new(BIO_s_file()) returned NULL");
	if (BIO_read_filename(bio, uri->local) <= 0) {
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
__certificate_get_resources(X509 *cert, struct resources *resources,
    int addr_nid, int asn_nid, int bad_addr_nid, int bad_asn_nid,
    char const *policy_rfc, char const *bad_ext_rfc)
{
	X509_EXTENSION *ext;
	int nid;
	int i;
	int error;
	bool ip_ext_found = false;
	bool asn_ext_found = false;

	/* Reference: X509_get_ext_d2i */
	/* rfc6487#section-2 */

	for (i = 0; i < X509_get_ext_count(cert); i++) {
		ext = X509_get_ext(cert, i);
		nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));

		if (nid == addr_nid) {
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

		} else if (nid == asn_nid) {
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

		} else if (nid == bad_addr_nid) {
			return pr_err("Certificate has an RFC%s policy, but contains an RFC%s IP extension.",
			    policy_rfc, bad_ext_rfc);
		} else if (nid == bad_asn_nid) {
			return pr_err("Certificate has an RFC%s policy, but contains an RFC%s ASN extension.",
			    policy_rfc, bad_ext_rfc);
		}
	}

	if (!ip_ext_found && !asn_ext_found)
		return pr_err("Certificate lacks both IP and AS extension.");

	return 0;
}

int
certificate_get_resources(X509 *cert, struct resources *resources)
{
	enum rpki_policy policy;

	policy = resources_get_policy(resources);
	switch (policy) {
	case RPKI_POLICY_RFC6484:
		return __certificate_get_resources(cert, resources,
		    NID_sbgp_ipAddrBlock, NID_sbgp_autonomousSysNum,
		    nid_ipAddrBlocksv2(), nid_autonomousSysIdsv2(),
		    "6484", "8360");
	case RPKI_POLICY_RFC8360:
		return __certificate_get_resources(cert, resources,
		    nid_ipAddrBlocksv2(), nid_autonomousSysIdsv2(),
		    NID_sbgp_ipAddrBlock, NID_sbgp_autonomousSysNum,
		    "8360", "6484");
	}

	return pr_crit("Unknown policy: %u", policy);
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

static bool
is_rsync_uri(GENERAL_NAME *name)
{
	return name->type == GEN_URI && is_rsync(name->d.GN_URI);
}

static int
handle_rpkiManifest(struct rpki_uri *uri, void *arg)
{
	struct rpki_uri *mft = arg;
	*mft = *uri;
	uri->global = NULL;
	uri->local = NULL;
	return 0;
}

static int
handle_caRepository(struct rpki_uri *uri, void *arg)
{
	pr_debug("caRepository: %s", uri->global);
	return download_files(uri);
}

static int
handle_signedObject(struct rpki_uri *uri, void *arg)
{
	struct certificate_refs *refs = arg;
	pr_debug("signedObject: %s", uri->global);
	refs->signedObject = uri->global;
	uri->global = NULL;
	return 0;
}

static int
handle_bc(X509_EXTENSION *ext, void *arg)
{
	BASIC_CONSTRAINTS *bc;
	int error;

	bc = X509V3_EXT_d2i(ext);
	if (bc == NULL)
		return cannot_decode(ext_bc());

	/*
	 * 'The issuer determines whether the "cA" boolean is set.'
	 * ................................. Uh-huh. So nothing then.
	 * Well, libcrypto should do the RFC 5280 thing with it anyway.
	 */

	error = (bc->pathlen == NULL)
	    ? 0
	    : pr_err("%s extension contains a Path Length Constraint.",
	          ext_bc()->name);

	BASIC_CONSTRAINTS_free(bc);
	return error;
}

static int
handle_ski_ca(X509_EXTENSION *ext, void *arg)
{
	ASN1_OCTET_STRING *ski;
	int error;

	ski = X509V3_EXT_d2i(ext);
	if (ski == NULL)
		return cannot_decode(ext_ski());

	error = validate_public_key_hash(arg, ski);

	ASN1_OCTET_STRING_free(ski);
	return error;
}

static int
handle_ski_ee(X509_EXTENSION *ext, void *arg)
{
	struct ski_arguments *args;
	ASN1_OCTET_STRING *ski;
	OCTET_STRING_t *sid;
	int error;

	ski = X509V3_EXT_d2i(ext);
	if (ski == NULL)
		return cannot_decode(ext_ski());

	args = arg;
	error = validate_public_key_hash(args->cert, ski);
	if (error)
		goto end;

	/* rfc6488#section-2.1.6.2 */
	/* rfc6488#section-3.1.c 2/2 */
	sid = args->sid;
	if (ski->length != sid->size
	    || memcmp(ski->data, sid->buf, sid->size) != 0) {
		error = pr_err("The EE certificate's subjectKeyIdentifier does not equal the Signed Object's sid.");
	}

end:
	ASN1_OCTET_STRING_free(ski);
	return error;
}

static bool
extension_equals(X509_EXTENSION *ext1, X509_EXTENSION *ext2)
{
	int crit1;
	int crit2;
	ASN1_OCTET_STRING *data1;
	ASN1_OCTET_STRING *data2;

	crit1 = X509_EXTENSION_get_critical(ext1);
	crit2 = X509_EXTENSION_get_critical(ext2);
	if (crit1 != crit2)
		return false;

	data1 = X509_EXTENSION_get_data(ext1);
	data2 = X509_EXTENSION_get_data(ext2);
	if (data1->length != data2->length)
		return false;
	if (data1->type != data2->type)
		return false;
	if (data1->flags != data2->flags)
		return false;
	if (memcmp(data1->data, data2->data, data1->length) != 0)
		return false;

	return true;
}

static int
handle_aki_ta(X509_EXTENSION *aki, void *arg)
{
	X509 *cert = arg;
	X509_EXTENSION *other;
	int i;

	for (i = 0; i < X509_get_ext_count(cert); i++) {
		other = X509_get_ext(cert, i);
		if (OBJ_obj2nid(X509_EXTENSION_get_object(other)) == ext_ski()->nid) {
			if (extension_equals(aki, other))
				return 0;

			return pr_err("The '%s' does not equal the '%s'.",
			    ext_aki()->name, ext_ski()->name);
		}
	}

	pr_err("Certificate lacks the '%s' extension.", ext_ski()->name);
	return -ESRCH;
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
		return cannot_decode(ext_ku());

	if (ku->length == 0) {
		error = pr_err("%s bit string has no enabled bits.",
		    ext_ku()->name);
		goto end;
	}

	memset(data, 0, sizeof(data));
	memcpy(data, ku->data, ku->length);

	if (ku->data[0] != byte1) {
		error = pr_err("Illegal key usage flag string: %d%d%d%d%d%d%d%d%d",
		    !!(ku->data[0] & 0x80u), !!(ku->data[0] & 0x40u),
		    !!(ku->data[0] & 0x20u), !!(ku->data[0] & 0x10u),
		    !!(ku->data[0] & 0x08u), !!(ku->data[0] & 0x04u),
		    !!(ku->data[0] & 0x02u), !!(ku->data[0] & 0x01u),
		    !!(ku->data[1] & 0x80u));
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
	struct certificate_refs *refs = arg;
	STACK_OF(DIST_POINT) *crldp;
	DIST_POINT *dp;
	GENERAL_NAMES *names;
	GENERAL_NAME *name;
	int i;
	int error = 0;
	char const *error_msg;

	crldp = X509V3_EXT_d2i(ext);
	if (crldp == NULL)
		return cannot_decode(ext_cdp());

	if (sk_DIST_POINT_num(crldp) != 1) {
		error = pr_err("The %s extension has %d distribution points. (1 expected)",
		    ext_cdp()->name, sk_DIST_POINT_num(crldp));
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
		if (is_rsync_uri(name)) {
			/*
			 * Since we're parsing and validating the manifest's CRL
			 * at some point, I think that all we need to do now is
			 * compare this CRL URI to that one's.
			 *
			 * But there is a problem:
			 * The manifest's CRL might not have been parsed at this
			 * point. In fact, it's guaranteed to not have been
			 * parsed if the certificate we're validating is the EE
			 * certificate of the manifest itself.
			 *
			 * So we will store the URI in @refs, and validate it
			 * later.
			 */
			error = ia5s2string(name->d.GN_URI, &refs->crldp);
			goto end;
		}
	}

	error_msg = "lacks an RSYNC URI";

dist_point_error:
	error = pr_err("The %s extension's distribution point %s.",
	    ext_cdp()->name, error_msg);

end:
	sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
	return error;
}

/**
 * The RFC does not explain AD validation very well. This is personal
 * interpretation, influenced by Tim Bruijnzeels's response
 * (https://mailarchive.ietf.org/arch/msg/sidr/4ycmff9jEU4VU9gGK5RyhZ7JYsQ)
 * (I'm being a bit more lax than he suggested.)
 *
 * 1. Only one NID needs to be searched at a time. (This is currently somewhat
 *    of a coincidence, and will probably be superseded at some point. But I'm
 *    not going to complicate this until it's necessary.)
 * 2. The NID MUST be found, otherwise the certificate is invalid.
 * 3. The NID can be found more than once.
 * 4. All access descriptions that match the NID must be URLs.
 * 5. Precisely one of those matches will be an RSYNC URL, and it's the only one
 *    we are required to support.
 *    (I would have gone with "at least one of those matches", but I don't know
 *    what to do with the other ones.)
 * 6. Other access descriptions that do not match the NID are allowed and
 *    supposed to be ignored.
 * 7. Other access descriptions that match the NID but do not have RSYNC URIs
 *    are also allowed, and also supposed to be ignored.
 */
static int
handle_ad(char const *ia_name, SIGNATURE_INFO_ACCESS *ia,
    char const *ad_name, int ad_nid,
    int (*cb)(struct rpki_uri *, void *), void *arg)
{
	ACCESS_DESCRIPTION *ad;
	struct rpki_uri uri;
	bool found = false;
	int i;
	int error;

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(ia, i);
		if (OBJ_obj2nid(ad->method) == ad_nid) {
			error = uri_init_ad(&uri, ad);
			if (error == ENOTRSYNC)
				continue;
			if (error)
				return error;

			if (found) {
				uri_cleanup(&uri);
				return pr_err("Extension '%s' has multiple '%s' RSYNC URIs.",
				    ia_name, ad_name);
			}

			error = cb(&uri, arg);
			if (error) {
				uri_cleanup(&uri);
				return error;
			}

			uri_cleanup(&uri);
			found = true;
		}
	}

	if (!found) {
		pr_err("Extension '%s' lacks a '%s' RSYNC URI.", ia_name,
		    ad_name);
		return -ESRCH;
	}

	return 0;
}

static int
handle_caIssuers(struct rpki_uri *uri, void *arg)
{
	struct certificate_refs *refs = arg;
	/*
	 * Bringing the parent certificate's URI all the way
	 * over here is too much trouble, so do the handle_cdp()
	 * hack.
	 */
	refs->caIssuers = uri->global;
	uri->global = NULL;
	return 0;
}

static int
handle_aia(X509_EXTENSION *ext, void *arg)
{
	AUTHORITY_INFO_ACCESS *aia;
	int error;

	aia = X509V3_EXT_d2i(ext);
	if (aia == NULL)
		return cannot_decode(ext_aia());

	error = handle_ad("AIA", aia, "caIssuers", NID_ad_ca_issuers,
	    handle_caIssuers, arg);

	AUTHORITY_INFO_ACCESS_free(aia);
	return error;
}

static int
handle_sia_ca(X509_EXTENSION *ext, void *arg)
{
	SIGNATURE_INFO_ACCESS *sia;
	int error;

	sia = X509V3_EXT_d2i(ext);
	if (sia == NULL)
		return cannot_decode(ext_sia());

	/* rsync */
	error = handle_ad("SIA", sia, "caRepository", NID_caRepository,
	    handle_caRepository, NULL);
	if (error)
		goto end;

	/*
	 * Store the manifest URI in @mft.
	 * (We won't actually touch the manifest until we know the certificate
	 * is fully valid.)
	 */
	error = handle_ad("SIA", sia, "rpkiManifest", nid_rpkiManifest(),
	    handle_rpkiManifest, arg);

end:
	AUTHORITY_INFO_ACCESS_free(sia);
	return error;
}

static int
handle_sia_ee(X509_EXTENSION *ext, void *arg)
{
	SIGNATURE_INFO_ACCESS *sia;
	int error;

	sia = X509V3_EXT_d2i(ext);
	if (sia == NULL)
		return cannot_decode(ext_sia());

	error = handle_ad("SIA", sia, "signedObject", nid_signedObject(),
	    handle_signedObject, arg);

	AUTHORITY_INFO_ACCESS_free(sia);
	return error;
}

static int
handle_cp(X509_EXTENSION *ext, void *arg)
{
	enum rpki_policy *policy = arg;
	CERTIFICATEPOLICIES *cp;
	POLICYINFO *pi;
	POLICYQUALINFO *pqi;
	int error, nid_cp, nid_qt_cps, pqi_num;

	error = 0;
	cp = X509V3_EXT_d2i(ext);
	if (cp == NULL)
		return cannot_decode(ext_cp());

	if (sk_POLICYINFO_num(cp) != 1) {
		error = pr_err("The %s extension has %d policy information's. (1 expected)",
		    ext_cp()->name, sk_POLICYINFO_num(cp));
		goto end;
	}

	/* rfc7318#section-2 and consider rfc8360#section-4.2.1 */
	pi = sk_POLICYINFO_value(cp, 0);
	nid_cp = OBJ_obj2nid(pi->policyid);
	if (nid_cp == nid_certPolicyRpki()) {
		if (policy != NULL)
			*policy = RPKI_POLICY_RFC6484;
	} else if (nid_cp == nid_certPolicyRpkiV2()) {
		pr_debug("Found RFC8360 policy!");
		if (policy != NULL)
			*policy = RPKI_POLICY_RFC8360;
	} else {
		error = pr_err("Invalid certificate policy OID, isn't 'id-cp-ipAddr-asNumber' nor 'id-cp-ipAddr-asNumber-v2'");
		goto end;
	}

	/* Exactly one policy qualifier MAY be included (so none is also valid) */
	if (pi->qualifiers == NULL)
		goto end;

	pqi_num = sk_POLICYQUALINFO_num(pi->qualifiers);
	if (pqi_num == 0)
		goto end;
	if (pqi_num != 1) {
		error = pr_err("The %s extension has %d policy qualifiers. (none or only 1 expected)",
		    ext_cp()->name, pqi_num);
		goto end;
	}

	pqi = sk_POLICYQUALINFO_value(pi->qualifiers, 0);
	nid_qt_cps = OBJ_obj2nid(pqi->pqualid);
	if (nid_qt_cps != NID_id_qt_cps) {
		error = pr_err("Policy qualifier ID isn't Certification Practice Statement (CPS)");
		goto end;
	}
end:
	CERTIFICATEPOLICIES_free(cp);
	return error;
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

int
certificate_validate_extensions_ta(X509 *cert, struct rpki_uri *mft,
    enum rpki_policy *policy)
{
	struct extension_handler handlers[] = {
	   /* ext        reqd   handler        arg       */
	    { ext_bc(),  true,  handle_bc,               },
	    { ext_ski(), true,  handle_ski_ca, cert      },
	    { ext_aki(), false, handle_aki_ta, cert      },
	    { ext_ku(),  true,  handle_ku_ca,            },
	    { ext_sia(), true,  handle_sia_ca, mft       },
	    { ext_cp(),  true,  handle_cp,     policy    },
	    { ext_ir(),  false, handle_ir,               },
	    { ext_ar(),  false, handle_ar,               },
	    { ext_ir2(), false, handle_ir,               },
	    { ext_ar2(), false, handle_ar,               },
	    { NULL },
	};

	return handle_extensions(handlers, X509_get0_extensions(cert));
}

int
certificate_validate_extensions_ca(X509 *cert, struct rpki_uri *mft,
    struct certificate_refs *refs, enum rpki_policy *policy)
{
	struct extension_handler handlers[] = {
	   /* ext        reqd   handler        arg       */
	    { ext_bc(),  true,  handle_bc,               },
	    { ext_ski(), true,  handle_ski_ca, cert      },
	    { ext_aki(), true,  handle_aki,              },
	    { ext_ku(),  true,  handle_ku_ca,            },
	    { ext_cdp(), true,  handle_cdp,    refs      },
	    { ext_aia(), true,  handle_aia,    refs      },
	    { ext_sia(), true,  handle_sia_ca, mft       },
	    { ext_cp(),  true,  handle_cp,     policy    },
	    { ext_ir(),  false, handle_ir,               },
	    { ext_ar(),  false, handle_ar,               },
	    { ext_ir2(), false, handle_ir,               },
	    { ext_ar2(), false, handle_ar,               },
	    { NULL },
	};

	return handle_extensions(handlers, X509_get0_extensions(cert));
}

int
certificate_validate_extensions_ee(X509 *cert, OCTET_STRING_t *sid,
    struct certificate_refs *refs, enum rpki_policy *policy)
{
	struct ski_arguments ski_args;
	struct extension_handler handlers[] = {
	   /* ext        reqd   handler        arg       */
	    { ext_ski(), true,  handle_ski_ee, &ski_args },
	    { ext_aki(), true,  handle_aki,              },
	    { ext_ku(),  true,  handle_ku_ee,            },
	    { ext_cdp(), true,  handle_cdp,    refs      },
	    { ext_aia(), true,  handle_aia,    refs      },
	    { ext_sia(), true,  handle_sia_ee, refs      },
	    { ext_cp(),  true,  handle_cp,     policy    },
	    { ext_ir(),  false, handle_ir,               },
	    { ext_ar(),  false, handle_ar,               },
	    { ext_ir2(), false, handle_ir,               },
	    { ext_ar2(), false, handle_ar,               },
	    { NULL },
	};

	ski_args.cert = cert;
	ski_args.sid = sid;

	return handle_extensions(handlers, X509_get0_extensions(cert));
}

/* Boilerplate code for CA certificate validation and recursive traversal. */
int
certificate_traverse(struct rpp *rpp_parent, struct rpki_uri const *cert_uri,
    STACK_OF(X509_CRL) *crls, bool is_ta)
{
	struct validation *state;
	X509 *cert;
	struct rpki_uri mft;
	struct certificate_refs refs;
	enum rpki_policy policy;
	struct rpp *pp;
	int error;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;
	if (sk_X509_num(validation_certs(state)) >= config_get_max_cert_depth())
		return pr_err("Certificate chain maximum depth exceeded.");

	pr_debug_add("%s Certificate %s {", is_ta ? "TA" : "CA",
	    cert_uri->global);
	fnstack_push(cert_uri->global);
	memset(&refs, 0, sizeof(refs));

	/* -- Validate the certificate (@cert) -- */
	error = certificate_load(cert_uri, &cert);
	if (error)
		goto end1;
	if (!is_ta) {
		error = certificate_validate_chain(cert, crls);
		if (error)
			goto end2;
	}
	error = certificate_validate_rfc6487(cert, is_ta);
	if (error)
		goto end2;
	error = is_ta
	    ? certificate_validate_extensions_ta(cert, &mft, &policy)
	    : certificate_validate_extensions_ca(cert, &mft, &refs, &policy);
	if (error)
		goto end2;

	error = refs_validate_ca(&refs, is_ta, rpp_parent);
	if (error)
		goto end3;

	/* -- Validate the manifest (@mft) pointed by the certificate -- */
	error = validation_push_cert(state, cert_uri, cert, policy, is_ta);
	if (error)
		goto end3;

	error = handle_manifest(&mft, crls, &pp);
	if (error)
		goto end4;

	/* -- Validate & traverse the RPP (@pp) described by the manifest -- */
	error = rpp_traverse(pp);

	rpp_destroy(pp);
end4:
	validation_pop_cert(state); /* Error code is useless. */
end3:
	uri_cleanup(&mft);
	refs_cleanup(&refs);
end2:
	X509_free(cert);
end1:
	fnstack_pop();
	pr_debug_rm("}");
	return error;
}
