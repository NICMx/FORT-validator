#include "certificate.h"

#include <errno.h>
#include <stdint.h> /* SIZE_MAX */
#include <sys/socket.h>

#include "algorithm.h"
#include "config.h"
#include "extension.h"
#include "log.h"
#include "nid.h"
#include "str.h"
#include "thread_var.h"
#include "asn1/decode.h"
#include "asn1/oid.h"
#include "asn1/asn1c/IPAddrBlocks.h"
#include "crypto/hash.h"
#include "object/bgpsec.h"
#include "object/name.h"
#include "object/manifest.h"
#include "object/signed_object.h"
#include "rrdp/rrdp_loader.h"
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

struct sia_uri {
	uint8_t position;
	struct rpki_uri *uri;
};

struct sia_ca_uris {
	struct sia_uri caRepository;
	struct sia_uri rpkiNotify;
	struct sia_uri mft;
};

struct bgpsec_ski {
	X509 *cert;
	unsigned char **ski_data;
};

/* Callback method to fetch repository objects */
typedef int (access_method_exec)(struct sia_ca_uris *);

static void
sia_ca_uris_init(struct sia_ca_uris *sia_uris)
{
	sia_uris->caRepository.uri = NULL;
	sia_uris->rpkiNotify.uri = NULL;
	sia_uris->mft.uri = NULL;
}

static void
sia_ca_uris_cleanup(struct sia_ca_uris *sia_uris)
{
	if (sia_uris->caRepository.uri != NULL)
		uri_refput(sia_uris->caRepository.uri);
	if (sia_uris->rpkiNotify.uri != NULL)
		uri_refput(sia_uris->rpkiNotify.uri);
	if (sia_uris->mft.uri != NULL)
		uri_refput(sia_uris->mft.uri);
}

static void
debug_serial_number(BIGNUM *number)
{
	char *number_str;

	number_str = BN_bn2dec(number);
	if (number_str == NULL) {
		crypto_err("Could not convert BN to string");
		return;
	}

	pr_debug("serial Number: %s", number_str);
	free(number_str);
}

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

	if (log_debug_enabled())
		debug_serial_number(number);

	error = x509stack_store_serial(validation_certstack(state), number);
	if (error)
		BN_free(number);

	return error;
}

static int
validate_signature_algorithm(X509 *cert)
{
	int nid = OBJ_obj2nid(X509_get0_tbs_sigalg(cert)->algorithm);
	return validate_certificate_signature_algorithm(nid, "Certificate");
}

static int
validate_issuer(X509 *cert, bool is_ta)
{
	X509_NAME *issuer;
	struct rfc5280_name *name;
	int error;

	issuer = X509_get_issuer_name(cert);

	if (!is_ta)
		return validate_issuer_name("Certificate", issuer);

	/* TODO wait. Shouldn't we check subject == issuer? */

	error = x509_name_decode(issuer, "issuer", &name);
	if (error)
		return error;
	pr_debug("Issuer: %s", x509_name_commonName(name));

	x509_name_put(name);
	return 0;
}

/*
 * Compare public keys, call @diff_alg_cb when the algorithm is different, call
 * @diff_pk_cb when the public key is different; return 0 if both are equal.
 */
static int
spki_cmp(X509_PUBKEY *tal_spki, X509_PUBKEY *cert_spki,
    int (*diff_alg_cb)(void), int (*diff_pk_cb)(void))
{
	ASN1_OBJECT *tal_alg;
	ASN1_OBJECT *cert_alg;

	unsigned char const *tal_spk, *cert_spk;
	int tal_spk_len, cert_spk_len;

	int ok;

	ok = X509_PUBKEY_get0_param(&tal_alg, &tal_spk, &tal_spk_len, NULL,
	    tal_spki);
	if (!ok)
		return crypto_err("X509_PUBKEY_get0_param() 1 returned %d", ok);
	ok = X509_PUBKEY_get0_param(&cert_alg, &cert_spk, &cert_spk_len, NULL,
	    cert_spki);
	if (!ok)
		return crypto_err("X509_PUBKEY_get0_param() 2 returned %d", ok);

	if (OBJ_cmp(tal_alg, cert_alg) != 0)
		return diff_alg_cb();
	if (tal_spk_len != cert_spk_len)
		return diff_pk_cb();
	if (memcmp(tal_spk, cert_spk, cert_spk_len) != 0)
		return diff_pk_cb();

	return 0;
}

/** Call whenever the public key is different and the subject is the same**/
static int
cert_different_pk_err(void)
{
	return 1;
}

/*
 * Beware: this function skips a lot (maybe all) RPKI validations for a signed
 * object, and clearly expects that the signed object has at least one
 * certificate.
 *
 * Allocates @result, don't forget to release it.
 *
 * It has been placed here to minimize the risk of misuse.
 */
static int
cert_from_signed_object(struct rpki_uri *uri, uint8_t **result, int *size)
{
	struct signed_object sobj;
	ANY_t *cert;
	unsigned char *tmp;
	int error;

	error = signed_object_decode(&sobj, uri);
	if (error)
		return error;

	cert = sobj.sdata.decoded->certificates->list.array[0];

	tmp = malloc(cert->size);
	if (tmp == NULL) {
		signed_object_cleanup(&sobj);
		return pr_enomem();
	}

	memcpy(tmp, cert->buf, cert->size);

	*result = tmp;
	(*size) = cert->size;

	signed_object_cleanup(&sobj);
	return 0;
}

static int
check_dup_public_key(bool *duplicated, char const *file, void *arg)
{
	X509 *curr_cert = arg; /* Current cert */
	X509 *rcvd_cert;
	X509_PUBKEY *curr_pk, *rcvd_pk;
	struct rpki_uri *uri;
	uint8_t *tmp;
	int tmp_size;
	int error;

	uri = NULL;
	rcvd_cert = NULL;
	tmp_size = 0;

	error = uri_create_rsync_str(&uri, file, strlen(file));
	if (error)
		return error;

	/* Check if it's '.cer', otherwise treat as a signed object */
	if (uri_is_certificate(uri)) {
		error = certificate_load(uri, &rcvd_cert);
		if (error)
			goto free_uri;
	} else {
		error = cert_from_signed_object(uri, &tmp, &tmp_size);
		if (error)
			goto free_uri;

		rcvd_cert = d2i_X509(NULL, (const unsigned char **) &tmp,
		    tmp_size);
		free(tmp); /* Release at once */
		if (rcvd_cert == NULL) {
			error = crypto_err("Signed object's '%s' 'certificate' element does not decode into a Certificate",
			    uri_get_printable(uri));
			goto free_uri;
		}
	}

	curr_pk = X509_get_X509_PUBKEY(curr_cert);
	if (curr_pk == NULL) {
		error = crypto_err("X509_get_X509_PUBKEY() returned NULL");
		goto free_cert;
	}

	rcvd_pk = X509_get_X509_PUBKEY(rcvd_cert);
	if (rcvd_pk == NULL) {
		error = crypto_err("X509_get_X509_PUBKEY() returned NULL");
		goto free_cert;
	}

	/*
	 * The function response will be:
	 *   < 0 if there's an error
	 *   = 0 if the PKs are equal
	 *   > 0 if the PKs are different
	 */
	error = spki_cmp(curr_pk, rcvd_pk, cert_different_pk_err,
	    cert_different_pk_err);

	if (error < 0)
		goto free_cert;

	/* No error, a positive value means the name is duplicated */
	if (error)
		(*duplicated) = true;
	error = 0;

free_cert:
	X509_free(rcvd_cert);
free_uri:
	uri_refput(uri);
	return error;
}

static int
validate_subject(X509 *cert)
{
	struct validation *state;
	struct rfc5280_name *name;
	int error;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	error = x509_name_decode(X509_get_subject_name(cert), "subject", &name);
	if (error)
		return error;
	pr_debug("Subject: %s", x509_name_commonName(name));

	error = x509stack_store_subject(validation_certstack(state), name,
	    check_dup_public_key, cert);

	x509_name_put(name);
	return error;
}

static int
root_different_alg_err(void)
{
	return pr_err("TAL's public key algorithm is different than the root certificate's public key algorithm.");
}

static int
root_different_pk_err(void)
{
	return pr_err("TAL's public key is different than the root certificate's public key.");
}

static int
validate_spki(X509_PUBKEY *cert_spki)
{
	struct validation *state;
	struct tal *tal;

	X509_PUBKEY *tal_spki;
	unsigned char const *_tal_spki;
	size_t _tal_spki_len;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	tal = validation_tal(state);
	if (tal == NULL)
		pr_crit("Validation state has no TAL.");

	/*
	 * We have a problem at this point:
	 *
	 * RFC 8630 says "The public key used to verify the trust anchor MUST be
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
	 *
	 * Reminder: "X509_PUBKEY" and "Subject Public Key Info" are synonyms.
	 */

	fnstack_push(tal_get_file_name(tal));
	tal_get_spki(tal, &_tal_spki, &_tal_spki_len);
	tal_spki = d2i_X509_PUBKEY(NULL, &_tal_spki, _tal_spki_len);
	fnstack_pop();

	if (tal_spki == NULL) {
		crypto_err("The TAL's public key cannot be decoded");
		goto fail1;
	}

	if (spki_cmp(tal_spki, cert_spki, root_different_alg_err,
	    root_different_pk_err) != 0)
		goto fail2;

	X509_PUBKEY_free(tal_spki);
	validation_pubkey_valid(state);
	return 0;

fail2:
	X509_PUBKEY_free(tal_spki);
fail1:
	validation_pubkey_invalid(state);
	return -EINVAL;
}

/*
 * RFC 7935 Section 3:
 * "The RSA key pairs used to compute the signatures MUST have a
 * 2048-bit modulus and a public exponent (e) of 65,537."
 */
static int
validate_subject_public_key(X509_PUBKEY *pubkey)
{
#define MODULUS 2048
#define EXPONENT "65537"
	const RSA *rsa;
	const BIGNUM *exp;
	char *exp_str;
	int modulus;
	int error;

	rsa = EVP_PKEY_get0_RSA(X509_PUBKEY_get0(pubkey));
	if (rsa == NULL)
		return crypto_err("EVP_PKEY_get0_RSA() returned NULL");

	modulus = RSA_bits(rsa);
	if (modulus != MODULUS)
		return pr_err("Certificate's subjectPublicKey (RSAPublicKey) modulus is %d bits, not %d bits.",
		    modulus, MODULUS);

	RSA_get0_key(rsa, NULL, &exp, NULL);
	if (exp == NULL)
		return pr_err("Certificate's subjectPublicKey (RSAPublicKey) exponent isn't set, must be "
		    EXPONENT " bits.");

	exp_str = BN_bn2dec(exp);
	if (exp_str == NULL)
		return crypto_err("Couldn't get subjectPublicKey exponent string");

	if (strcmp(EXPONENT, exp_str) != 0) {
		error = pr_err("Certificate's subjectPublicKey (RSAPublicKey) exponent is %s, must be "
		    EXPONENT " bits.", exp_str);
		free(exp_str);
		return error;
	}
	free(exp_str);

	return 0;
#undef EXPONENT
#undef MODULUS
}

static int
validate_public_key(X509 *cert, enum cert_type type)
{
	X509_PUBKEY *pubkey;
	X509_ALGOR *pa;
	ASN1_OBJECT *alg;
	int ok;
	int error;

	/* Reminder: X509_PUBKEY is the same as SubjectPublicKeyInfo. */
	pubkey = X509_get_X509_PUBKEY(cert);
	if (pubkey == NULL)
		return crypto_err("X509_get_X509_PUBKEY() returned NULL");

	ok = X509_PUBKEY_get0_param(&alg, NULL, NULL, &pa, pubkey);
	if (!ok)
		return crypto_err("X509_PUBKEY_get0_param() returned %d", ok);

	if (type == BGPSEC)
		return validate_certificate_public_key_algorithm_bgpsec(pa);

	error = validate_certificate_public_key_algorithm(pa);
	if (error)
		return error;

	error = validate_subject_public_key(pubkey);
	if (error)
		return error;

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

	if (type == TA) {
		error = validate_spki(pubkey);
		if (error)
			return error;
	}

	return 0;
}

int
certificate_validate_rfc6487(X509 *cert, enum cert_type type)
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
	error = validate_issuer(cert, type == TA);
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
	/* Fragment of rfc8630#section-2.3 */
	error = validate_public_key(cert, type);
	if (error)
		return error;

	/* We'll validate extensions later. */
	return 0;
}

struct progress {
	size_t offset;
	size_t remaining;
};

/**
 * Skip the "T" part of a TLV.
 */
static void
skip_t(ANY_t *content, struct progress *p, unsigned int tag)
{
	/*
	 * BTW: I made these errors critical because the signedData is supposed
	 * to be validated by this point.
	 */

	if (content->buf[p->offset] != tag)
		pr_crit("Expected tag 0x%x, got 0x%x", tag,
		    content->buf[p->offset]);

	if (p->remaining == 0)
		pr_crit("Buffer seems to be truncated");
	p->offset++;
	p->remaining--;
}

/**
 * Skip the "TL" part of a TLV.
 */
static void
skip_tl(ANY_t *content, struct progress *p, unsigned int tag)
{
	ssize_t len_len; /* Length of the length field */
	ber_tlv_len_t value_len; /* Length of the value */

	skip_t(content, p, tag);

	len_len = ber_fetch_length(true, &content->buf[p->offset], p->remaining,
	    &value_len);
	if (len_len == -1)
		pr_crit("Could not decipher length (Cause is unknown)");
	if (len_len == 0)
		pr_crit("Buffer seems to be truncated");

	p->offset += len_len;
	p->remaining -= len_len;
}

static void
skip_tlv(ANY_t *content, struct progress *p, unsigned int tag)
{
	int is_constructed;
	int skip;

	is_constructed = BER_TLV_CONSTRUCTED(&content->buf[p->offset]);

	skip_t(content, p, tag);

	skip = ber_skip_length(NULL, is_constructed, &content->buf[p->offset],
	    p->remaining);
	if (skip == -1)
		pr_crit("Could not skip length (Cause is unknown)");
	if (skip == 0)
		pr_crit("Buffer seems to be truncated");

	p->offset += skip;
	p->remaining -= skip;
}

/**
 * A structure that points to the LV part of a signedAttrs TLV.
 */
struct encoded_signedAttrs {
	const uint8_t *buffer;
	ber_tlv_len_t size;
};

static void
find_signedAttrs(ANY_t *signedData, struct encoded_signedAttrs *result)
{
#define INTEGER_TAG		0x02
#define SEQUENCE_TAG		0x30
#define SET_TAG			0x31

	struct progress p;
	ssize_t len_len;

	/* Reference: rfc5652-12.1.asn1 */

	p.offset = 0;
	p.remaining = signedData->size;

	/* SignedData: SEQUENCE */
	skip_tl(signedData, &p, SEQUENCE_TAG);

	/* SignedData.version: CMSVersion -> INTEGER */
	skip_tlv(signedData, &p, INTEGER_TAG);
	/* SignedData.digestAlgorithms: DigestAlgorithmIdentifiers -> SET */
	skip_tlv(signedData, &p, SET_TAG);
	/* SignedData.encapContentInfo: EncapsulatedContentInfo -> SEQUENCE */
	skip_tlv(signedData, &p, SEQUENCE_TAG);
	/* SignedData.certificates: CertificateSet -> SET */
	skip_tlv(signedData, &p, 0xA0);
	/* SignedData.signerInfos: SignerInfos -> SET OF SEQUENCE */
	skip_tl(signedData, &p, SET_TAG);
	skip_tl(signedData, &p, SEQUENCE_TAG);

	/* SignedData.signerInfos.version: CMSVersion -> INTEGER */
	skip_tlv(signedData, &p, INTEGER_TAG);
	/*
	 * SignedData.signerInfos.sid: SignerIdentifier -> CHOICE -> always
	 * subjectKeyIdentifier, which is a [0].
	 */
	skip_tlv(signedData, &p, 0x80);
	/* SignedData.signerInfos.digestAlgorithm: DigestAlgorithmIdentifier
	 * -> AlgorithmIdentifier -> SEQUENCE */
	skip_tlv(signedData, &p, SEQUENCE_TAG);

	/* SignedData.signerInfos.signedAttrs: SignedAttributes -> SET */
	/* We will need to replace the tag 0xA0 with 0x31, so skip it as well */
	skip_t(signedData, &p, 0xA0);

	result->buffer = &signedData->buf[p.offset];
	len_len = ber_fetch_length(true, result->buffer,
	    p.remaining, &result->size);
	if (len_len == -1)
		pr_crit("Could not decipher length (Cause is unknown)");
	if (len_len == 0)
		pr_crit("Buffer seems to be truncated");
	result->size += len_len;
}

/*
 * TODO (next iteration) there exists a thing called "PKCS7_NOVERIFY", which
 * skips unnecessary validations when using the PKCS7 API. Maybe the methods
 * we're using have something similar.
 */
int
certificate_validate_signature(X509 *cert, ANY_t *signedData,
    SignatureValue_t *signature)
{
	static const uint8_t EXPLICIT_SET_OF_TAG = 0x31;

	X509_PUBKEY *public_key;
	EVP_MD_CTX *ctx;
	struct encoded_signedAttrs signedAttrs;
	int error;

	public_key = X509_get_X509_PUBKEY(cert);
	if (public_key == NULL)
		return crypto_err("Certificate seems to lack a public key");

	/* Create the Message Digest Context */
	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
		return crypto_err("EVP_MD_CTX_create() error");

	if (1 != EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL,
	    X509_PUBKEY_get0(public_key))) {
		error = crypto_err("EVP_DigestVerifyInit() error");
		goto end;
	}

	/*
	 * When the [signedAttrs] field is present
	 * (...),
	 * the result is the message
	 * digest of the complete DER encoding of the SignedAttrs value
	 * contained in the signedAttrs field.
	 * (...)
	 * A separate encoding
	 * of the signedAttrs field is performed for message digest calculation.
	 * The IMPLICIT [0] tag in the signedAttrs is not used for the DER
	 * encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
	 * encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
	 * tag, MUST be included in the message digest calculation along with
	 * the length and content octets of the SignedAttributes value.
	 *               (https://tools.ietf.org/html/rfc5652#section-5.4)
	 *
	 * FYI: IMPLICIT [0] is 0xA0, and EXPLICIT SET OF is 0x31.
	 *
	 * I can officially declare that these requirements are a gargantuan
	 * pain in the ass. Through the validation, we need access to the
	 * signedAttrs thingo in both encoded and decoded versions.
	 * (We need the decoded version for the sake of profile validation
	 * during validate_signed_attrs(), and the encoded version to check
	 * the signature of the SO right here.)
	 * Getting the encoded version is the problem. We have two options:
	 *
	 * 1. Re-encode the decoded version.
	 * 2. Extract the encoded version from the original BER SignedData.
	 *
	 * The first one sounded less efficient but more straightforward, but
	 * I couldn't pull it off because there's some memory bug with asn1c's
	 * encoding function that core dumps the fuck out of everything. It's
	 * caused by undefined behavior that triggers who knows where.
	 *
	 * There's another problem with that approach: If we DER-encode the
	 * signedAttrs, we have no guarantee that the signature will match
	 * because of the very real possibility that whoever signed used BER
	 * instead.
	 *
	 * One drawback for the second option is that obviously there's no API
	 * for it. asn1c encodes and decodes; there's no method for extracting
	 * a particular encoded object out of an encoded container. We need to
	 * do the parsing ourselves. But it's not that bad because of of
	 * ber_fetch_length() and ber_skip_length().
	 *
	 * Second option it is.
	 */

	find_signedAttrs(signedData, &signedAttrs);

	error = EVP_DigestVerifyUpdate(ctx, &EXPLICIT_SET_OF_TAG,
	    sizeof(EXPLICIT_SET_OF_TAG));
	if (1 != error) {
		error = crypto_err("EVP_DigestVerifyInit() error");
		goto end;
	}

	error = EVP_DigestVerifyUpdate(ctx, signedAttrs.buffer,
	    signedAttrs.size);
	if (1 != error) {
		error = crypto_err("EVP_DigestVerifyInit() error");
		goto end;
	}

	if (1 != EVP_DigestVerifyFinal(ctx, signature->buf, signature->size)) {
		error = crypto_err("Signed Object's signature is invalid");
		goto end;
	}

	error = 0;

end:
	EVP_MD_CTX_free(ctx);
	return error;
}

int
certificate_load(struct rpki_uri *uri, X509 **result)
{
	X509 *cert = NULL;
	BIO *bio;
	int error;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL)
		return crypto_err("BIO_new(BIO_s_file()) returned NULL");
	if (BIO_read_filename(bio, uri_get_local(uri)) <= 0) {
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

	if (crls == NULL)
		return 0; /* Certificate is TA; no chain validation needed. */

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

	X509_STORE_CTX_trusted_stack(ctx,
	    certstack_get_x509s(validation_certstack(state)));
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
	    (void **) &blocks, true, false);
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
handle_asn_extension(X509_EXTENSION *ext, struct resources *resources,
    bool allow_inherit)
{
	ASN1_OCTET_STRING *string;
	struct ASIdentifiers *ids;
	int error;

	string = X509_EXTENSION_get_data(ext);
	error = asn1_decode(string->data, string->length,
	    &asn_DEF_ASIdentifiers, (void **) &ids, true, false);
	if (error)
		return error;

	error = resources_add_asn(resources, ids, allow_inherit);

	ASN_STRUCT_FREE(asn_DEF_ASIdentifiers, ids);
	return error;
}

static int
__certificate_get_resources(X509 *cert, struct resources *resources,
    int addr_nid, int asn_nid, int bad_addr_nid, int bad_asn_nid,
    char const *policy_rfc, char const *bad_ext_rfc, bool allow_asn_inherit)
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

			pr_debug("IP {");
			error = handle_ip_extension(ext, resources);
			pr_debug("}");
			ip_ext_found = true;

			if (error)
				return error;

		} else if (nid == asn_nid) {
			if (asn_ext_found)
				return pr_err("Multiple AS extensions found.");
			if (!X509_EXTENSION_get_critical(ext))
				return pr_err("The AS extension is not marked as critical.");

			pr_debug("ASN {");
			error = handle_asn_extension(ext, resources,
			    allow_asn_inherit);
			pr_debug("}");
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
certificate_get_resources(X509 *cert, struct resources *resources,
    enum cert_type type)
{
	enum rpki_policy policy;

	policy = resources_get_policy(resources);
	switch (policy) {
	case RPKI_POLICY_RFC6484:
		return __certificate_get_resources(cert, resources,
		    NID_sbgp_ipAddrBlock, NID_sbgp_autonomousSysNum,
		    nid_ipAddrBlocksv2(), nid_autonomousSysIdsv2(),
		    "6484", "8360", type != BGPSEC);
	case RPKI_POLICY_RFC8360:
		return __certificate_get_resources(cert, resources,
		    nid_ipAddrBlocksv2(), nid_autonomousSysIdsv2(),
		    NID_sbgp_ipAddrBlock, NID_sbgp_autonomousSysNum,
		    "8360", "6484", type != BGPSEC);
	}

	pr_crit("Unknown policy: %u", policy);
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
handle_rpkiManifest(struct rpki_uri *uri, uint8_t pos, void *arg)
{
	struct sia_uri *mft = arg;
	mft->position = pos;
	mft->uri = uri;
	uri_refget(uri);
	return 0;
}

static int
handle_caRepository(struct rpki_uri *uri, uint8_t pos, void *arg)
{
	struct sia_uri *repo = arg;
	pr_debug("caRepository: %s", uri_get_printable(uri));
	repo->position = pos;
	repo->uri = uri;
	uri_refget(uri);
	return 0;
}

static int
handle_rpkiNotify(struct rpki_uri *uri, uint8_t pos, void *arg)
{
	struct sia_uri *notify = arg;
	pr_debug("rpkiNotify: %s", uri_get_printable(uri));
	notify->position = pos;
	notify->uri = uri;
	uri_refget(uri);
	return 0;
}

static int
handle_signedObject(struct rpki_uri *uri, uint8_t pos, void *arg)
{
	struct certificate_refs *refs = arg;
	pr_debug("signedObject: %s", uri_get_printable(uri));
	refs->signedObject = uri;
	uri_refget(uri);
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

static int
handle_ski_bgpsec(X509_EXTENSION *ext, void *arg)
{
	ASN1_OCTET_STRING *ski;
	struct bgpsec_ski *params;
	unsigned char *tmp;
	int error;

	ski = X509V3_EXT_d2i(ext);
	if (ski == NULL)
		return cannot_decode(ext_ski());

	params = arg;
	error = validate_public_key_hash(params->cert, ski);
	if (error)
		goto end;

	tmp = malloc(ski->length + 1);
	if (tmp == NULL)
		goto end;

	memcpy(tmp, ski->data, ski->length);
	tmp[ski->length] = '\0';
	*(params->ski_data) = tmp;

end:
	ASN1_OCTET_STRING_free(ski);
	return error;
}

static int
handle_aki_ta(X509_EXTENSION *ext, void *arg)
{
	struct AUTHORITY_KEYID_st *aki;
	ASN1_OCTET_STRING *ski;
	int error;

	aki = X509V3_EXT_d2i(ext);
	if (aki == NULL)
		return cannot_decode(ext_aki());
	if (aki->keyid == NULL) {
		error = pr_err("The '%s' extension lacks a keyIdentifier.",
		    ext_aki()->name);
		goto revert_aki;
	}

	ski = X509_get_ext_d2i(arg, NID_subject_key_identifier, NULL, NULL);
	if (ski == NULL) {
		pr_err("Certificate lacks the '%s' extension.",
		    ext_ski()->name);
		error = -ESRCH;
		goto revert_aki;
	}

	if (ASN1_OCTET_STRING_cmp(aki->keyid, ski) != 0) {
		error = pr_err("The '%s' does not equal the '%s'.",
		    ext_aki()->name, ext_ski()->name);
		goto revert_ski;
	}

	error = 0;

revert_ski:
	ASN1_BIT_STRING_free(ski);
revert_aki:
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
    char const *ad_name, int ad_nid, int uri_flags, bool required,
    int (*cb)(struct rpki_uri *, uint8_t, void *), void *arg)
{
# define AD_METHOD (uri_flags == URI_VALID_RSYNC ? \
	"RSYNC" : \
	((uri_flags == URI_VALID_HTTPS) ? "HTTPS" : "RSYNC/HTTPS"))
	ACCESS_DESCRIPTION *ad;
	struct rpki_uri *uri;
	bool found = false;
	unsigned int i;
	int error;

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(ia, i);
		if (OBJ_obj2nid(ad->method) == ad_nid) {
			error = uri_create_ad(&uri, ad, uri_flags);
			switch (error) {
			case 0:
				break;
			case ENOTRSYNC:
				continue;
			case ENOTHTTPS:
				continue;
			case ENOTSUPPORTED:
				continue;
			default:
				return error;
			}

			if (found) {
				uri_refput(uri);
				return pr_err("Extension '%s' has multiple '%s' %s URIs.",
				    ia_name, ad_name, AD_METHOD);
			}

			error = cb(uri, i, arg);
			if (error) {
				uri_refput(uri);
				return error;
			}

			uri_refput(uri);
			found = true;
		}
	}

	if (required && !found) {
		pr_err("Extension '%s' lacks a '%s' valid %s URI.", ia_name,
		    ad_name, AD_METHOD);
		return -ESRCH;
	}

	return 0;
}

static int
handle_caIssuers(struct rpki_uri *uri, uint8_t pos, void *arg)
{
	struct certificate_refs *refs = arg;
	/*
	 * Bringing the parent certificate's URI all the way
	 * over here is too much trouble, so do the handle_cdp()
	 * hack.
	 */
	refs->caIssuers = uri;
	uri_refget(uri);
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
	    URI_VALID_RSYNC, true, handle_caIssuers, arg);

	AUTHORITY_INFO_ACCESS_free(aia);
	return error;
}

static int
handle_sia_ca(X509_EXTENSION *ext, void *arg)
{
	SIGNATURE_INFO_ACCESS *sia;
	struct sia_ca_uris *uris = arg;
	int error;

	sia = X509V3_EXT_d2i(ext);
	if (sia == NULL)
		return cannot_decode(ext_sia());

	/* rsync, still the preferred and required */
	error = handle_ad("SIA", sia, "caRepository", NID_caRepository,
	    URI_VALID_RSYNC, true, handle_caRepository, &uris->caRepository);
	if (error)
		goto end;

	/* HTTPS RRDP */
	error = handle_ad("SIA", sia, "rpkiNotify", nid_rpkiNotify(),
	    URI_VALID_HTTPS, false, handle_rpkiNotify, &uris->rpkiNotify);
	if (error)
		goto end;

	/*
	 * Store the manifest URI in @mft.
	 * (We won't actually touch the manifest until we know the certificate
	 * is fully valid.)
	 */
	error = handle_ad("SIA", sia, "rpkiManifest", nid_rpkiManifest(),
	    URI_VALID_RSYNC, true, handle_rpkiManifest, &uris->mft);

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
	    URI_VALID_RSYNC, true, handle_signedObject, arg);

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

static int
handle_eku(X509_EXTENSION *ext, void *arg)
{
	EXTENDED_KEY_USAGE *eku;
	int nid;
	int error;

	eku = X509V3_EXT_d2i(ext);
	if (eku == NULL)
		return cannot_decode(ext_eku());

	/*
	 * RFC 8209 allows multiple KeyPurposeId, so look only for the one
	 * required and specified at section 3.1.3.2
	 */
	error = -ENOENT;
	while (sk_ASN1_OBJECT_num(eku) > 0) {
		nid = OBJ_obj2nid(sk_ASN1_OBJECT_pop(eku));
		if (nid == nid_bgpsecRouter()) {
			error = 0;
			goto end;
		}
	}

	if (error)
		pr_err("Extended Key Usage doesn't include id-kp-bgpsec-router.");
end:
	EXTENDED_KEY_USAGE_free(eku);
	return error;
}

/**
 * Validates the certificate extensions, Trust Anchor style.
 *
 * Depending on the Access Description preference at SIA, the rpki_uri's at
 * @sia_uris will be allocated.
 */
static int
certificate_validate_extensions_ta(X509 *cert, struct sia_ca_uris *sia_uris,
    enum rpki_policy *policy)
{
	struct extension_handler handlers[] = {
	   /* ext        reqd   handler        arg       */
	    { ext_bc(),  true,  handle_bc,               },
	    { ext_ski(), true,  handle_ski_ca, cert      },
	    { ext_aki(), false, handle_aki_ta, cert      },
	    { ext_ku(),  true,  handle_ku_ca,            },
	    { ext_sia(), true,  handle_sia_ca, sia_uris  },
	    { ext_cp(),  true,  handle_cp,     policy    },
	    { ext_ir(),  false, handle_ir,               },
	    { ext_ar(),  false, handle_ar,               },
	    { ext_ir2(), false, handle_ir,               },
	    { ext_ar2(), false, handle_ar,               },
	    { NULL },
	};

	return handle_extensions(handlers, X509_get0_extensions(cert));
}

/**
 * Validates the certificate extensions, (intermediate) Certificate Authority
 * style.
 *
 * Depending on the Access Description preference at SIA, the rpki_uri's at
 * @sia_uris will be allocated.
 * Also initializes the fourth argument with the references found in the
 * extensions.
 */
static int
certificate_validate_extensions_ca(X509 *cert, struct sia_ca_uris *sia_uris,
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
	    { ext_sia(), true,  handle_sia_ca, sia_uris  },
	    { ext_cp(),  true,  handle_cp,     policy    },
	    { ext_ir(),  false, handle_ir,               },
	    { ext_ar(),  false, handle_ar,               },
	    { ext_ir2(), false, handle_ir,               },
	    { ext_ar2(), false, handle_ar,               },
	    { NULL },
	};

	return handle_extensions(handlers, X509_get0_extensions(cert));
}

static int
certificate_validate_extensions_bgpsec(X509 *cert, unsigned char **ski,
    struct certificate_refs *refs, enum rpki_policy *policy)
{
	struct bgpsec_ski ski_param;
	struct extension_handler handlers[] = {
	   /* ext        reqd   handler            arg        */
	    { ext_ski(), true,  handle_ski_bgpsec, &ski_param },
	    { ext_aki(), true,  handle_aki,                   },
	    { ext_ku(),  true,  handle_ku_ee,                 },
	    { ext_cdp(), true,  handle_cdp,        refs       },
	    { ext_aia(), true,  handle_aia,        refs       },
	    { ext_cp(),  true,  handle_cp,         policy     },
	    { ext_eku(), true,  handle_eku,                   },
	    { ext_ar(),  false, handle_ar,                    },
	    { ext_ar2(), false, handle_ar,                    },
	    { NULL },
	};

	ski_param.cert = cert;
	ski_param.ski_data = ski;

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

static enum cert_type
get_certificate_type(X509 *cert, bool is_ta)
{
	if (is_ta)
		return TA;
	if (X509_get_ext_by_NID(cert, ext_bc()->nid, -1) >= 0)
		return CA;
	if (X509_get_ext_by_NID(cert, NID_ext_key_usage, -1) >= 0)
		return BGPSEC;
	return EE;
}

/*
 * It does some of the things from validate_issuer(), but we can not wait for
 * such validation, since at this point the RSYNC URI at AIA extension must be
 * verified to comply with rfc6487#section-4.8.7
 */
static int
force_aia_validation(struct rpki_uri *caIssuers, void *arg)
{
	X509 *son = arg;
	X509 *parent;
	struct rfc5280_name *son_name;
	struct rfc5280_name *parent_name;
	int error;

	pr_debug("AIA's URI didn't matched parent URI, doing AIA RSYNC");

	/* RSYNC is still the prefered access mechanism */
	error = download_files(caIssuers, false, false);
	if (error)
		return error;

	error = certificate_load(caIssuers, &parent);
	if (error)
		return error;

	error = x509_name_decode(X509_get_subject_name(parent), "subject",
	    &parent_name);
	if (error)
		goto free_parent;

	error = x509_name_decode(X509_get_issuer_name(son), "issuer",
	    &son_name);
	if (error)
		goto free_parent_name;

	if (x509_name_equals(parent_name, son_name))
		error = 0; /* Everything its ok */
	else
		error = pr_err("Certificate subject from AIA ('%s') isn't issuer of this certificate.",
		    uri_get_printable(caIssuers));

	x509_name_put(son_name);
free_parent_name:
	x509_name_put(parent_name);
free_parent:
	X509_free(parent);
	return error;
}

int
certificate_validate_aia(struct rpki_uri *caIssuers, X509 *cert)
{
	struct validation *state;
	struct rpki_uri *parent;

	if (caIssuers == NULL)
		pr_crit("Certificate's AIA was not recorded.");

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;
	parent = x509stack_peek_uri(validation_certstack(state));
	if (parent == NULL)
		pr_crit("Certificate has no parent.");

	/*
	 * There are two possible issues here, specifically at first level root
	 * certificate's childs:
	 *
	 * - Considering that the root certificate can be published at one or
	 *   more rsync or HTTPS URIs (RFC 8630), the validation is done
	 *   considering the first valid downloaded certificate URI from the
	 *   list of URIs; so, that URI doesn't necessarily matches AIA. And
	 *   this issue is more likely to happen if the 'shuffle-uris' flag
	 *   is active an a TAL has more than one rsync/HTTPS uri.
	 *
	 * - If the TAL has only one URI, and such URI is HTTPS, the root
	 *   certificate will be located at a distinct point that what it's
	 *   expected, so this might be an error if such certificate (root
	 *   certificate) isn't published at an rsync repository. See RFC 6487
	 *   section-4.8.7:
	 *
	 *   "The preferred URI access mechanisms is "rsync", and an rsync URI
	 *   [RFC5781] MUST be specified with an accessMethod value of
	 *   id-ad-caIssuers.  The URI MUST reference the point of publication
	 *   of the certificate where this Issuer is the subject (the issuer's
	 *   immediate superior certificate)."
	 *
	 * January 2020: this isn't a problem, all five RIRs are using one URI
	 * at their TALs, that matches AIA from the first level root certificate
	 * childs. Anyways, we'll try to consult the subject at IETF.
	 */
	if (uri_equals(caIssuers, parent))
		return 0;

	/*
	 * URI didn't match, try to match the immediate superior subject with
	 * the current issuer. This will force an RSYNC of AIA's URI, load
	 * the certificate and do the comparison.
	 */
	return force_aia_validation(caIssuers, cert);
}

/*
 * Verify that the manifest file actually exists at the local repository, if it
 * doesn't exist then discard the repository (which can result in a attempt
 * to fetch data from another repository).
 */
static int
verify_mft_loc(struct rpki_uri *mft_uri)
{
	if (!valid_file_or_dir(uri_get_local(mft_uri), true, false))
		return -EINVAL; /* Error already logged */

	return 0;
}

static int
exec_rrdp_method(struct sia_ca_uris *sia_uris)
{
	int error;

	error = rrdp_load(sia_uris->rpkiNotify.uri);
	if (error)
		return error;

	return verify_mft_loc(sia_uris->mft.uri);
}

static int
exec_rsync_method(struct sia_ca_uris *sia_uris)
{
	int error;

	error = download_files(sia_uris->caRepository.uri, false, false);
	if (error)
		return error;

	return verify_mft_loc(sia_uris->mft.uri);
}

/*
 * Currently only two access methods are supported, just consider those two:
 * rsync and RRDP. If a new access method is supported, this function must
 * change (and probably the sia_ca_uris struct as well).
 */
static int
use_access_method(struct sia_ca_uris *sia_uris,
    access_method_exec rsync_cb, access_method_exec rrdp_cb,
    bool *rsync_utilized)
{
	access_method_exec *cb_primary;
	access_method_exec *cb_secondary;
	rrdp_req_status_t rrdp_req_status;
	bool primary_rrdp;
	int error;

	/*
	 * RSYNC will always be present (at least for now, see
	 * rfc6487#section-4.8.8.1). If rsync is disabled, the cb will take
	 * care of that.
	 */
	(*rsync_utilized) = true;
	if (sia_uris->rpkiNotify.uri == NULL || !config_get_rrdp_enabled())
		return rsync_cb(sia_uris);

	/* RSYNC disabled, and RRDP is present, use it */
	if (!config_get_rsync_enabled()) {
		(*rsync_utilized) = false;
		return rrdp_cb(sia_uris);
	}

	/*
	 * There isn't any restriction about the preferred access method of
	 * children CAs being the same as the parent CA.
	 *
	 * Two possible scenarios arise:
	 * 1) CA Parent didn't utilized (or didn't had) and RRDP update
	 *    notification URI.
	 * 2) CA Parent successfully utilized an RRDP update notification URI.
	 *
	 * Step (1) is simple, do the check of the preferred access method.
	 * Step (2) must do something different.
	 * - If RRDP URI was already successfully visited, don't care
	 *   preference, don't execute access method.
	 */
	error = db_rrdp_uris_get_request_status(
	    uri_get_global(sia_uris->rpkiNotify.uri), &rrdp_req_status);
	if (error ==  0 && rrdp_req_status == RRDP_URI_REQ_VISITED) {
		(*rsync_utilized) = false;
		return 0;
	}

	/* Use CA's or configured priority? */
	if (config_get_rsync_priority() == config_get_rrdp_priority())
		primary_rrdp = sia_uris->caRepository.position
		    > sia_uris->rpkiNotify.position;
	else
		primary_rrdp = config_get_rsync_priority()
		    < config_get_rrdp_priority();

	cb_primary = primary_rrdp ? rrdp_cb : rsync_cb;
	cb_secondary = primary_rrdp ? rsync_cb : rrdp_cb;

	/* Try with the preferred; in case of error, try with the next one */
	error = cb_primary(sia_uris);
	if (!error) {
		(*rsync_utilized) = !primary_rrdp;
		return 0;
	}

	if (primary_rrdp) {
		if (error != -EPERM)
			pr_info("Couldn't fetch data from RRDP repository '%s', trying to fetch data now from '%s'.",
			    uri_get_global(sia_uris->rpkiNotify.uri),
			    uri_get_global(sia_uris->caRepository.uri));
		else
			pr_info("RRDP repository '%s' download/processing returned error previously, now I will try to fetch data from '%s'.",
			    uri_get_global(sia_uris->rpkiNotify.uri),
			    uri_get_global(sia_uris->caRepository.uri));
	} else {
		pr_info("Couldn't fetch data from repository '%s', trying to fetch data now from RRDP '%s'.",
		    uri_get_global(sia_uris->caRepository.uri),
		    uri_get_global(sia_uris->rpkiNotify.uri));
	}

	(*rsync_utilized) = primary_rrdp;
	return cb_secondary(sia_uris);
}

/** Boilerplate code for CA certificate validation and recursive traversal. */
int
certificate_traverse(struct rpp *rpp_parent, struct rpki_uri *cert_uri)
{
/** Is the CA certificate the TA certificate? */
#define IS_TA (rpp_parent == NULL)

	struct validation *state;
	int total_parents;
	STACK_OF(X509_CRL) *rpp_parent_crl;
	X509 *cert;
	struct sia_ca_uris sia_uris;
	struct certificate_refs refs;
	unsigned char *ski;
	enum rpki_policy policy;
	enum cert_type type;
	struct rpp *pp;
	bool mft_retry;
	int error;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;
	total_parents = certstack_get_x509_num(validation_certstack(state));
	if (total_parents >= config_get_max_cert_depth())
		return pr_err("Certificate chain maximum depth exceeded.");

	/* Debug cert type */
	if (IS_TA)
		pr_debug("TA Certificate '%s' {",
		    uri_get_printable(cert_uri));
	else
		pr_debug("Certificate '%s' {",
		    uri_get_printable(cert_uri));

	fnstack_push_uri(cert_uri);
	memset(&refs, 0, sizeof(refs));

	error = rpp_crl(rpp_parent, &rpp_parent_crl);
	if (error)
		goto revert_fnstack_and_debug;

	/* -- Validate the certificate (@cert) -- */
	error = certificate_load(cert_uri, &cert);
	if (error)
		goto revert_fnstack_and_debug;
	error = certificate_validate_chain(cert, rpp_parent_crl);
	if (error)
		goto revert_cert;

	sia_ca_uris_init(&sia_uris);
	type = get_certificate_type(cert, IS_TA);

	/* Debug cert type */
	switch (type) {
	case TA:
		break;
	case CA:
		pr_debug("Type: CA");
		break;
	case BGPSEC:
		pr_debug("Type: BGPsec EE");
		break;
	case EE:
		pr_debug("Type: unexpected, validated as CA");
		break;
	}

	error = certificate_validate_rfc6487(cert, type);
	if (error)
		goto revert_cert;
	switch (type) {
	case TA:
		error = certificate_validate_extensions_ta(cert, &sia_uris,
		    &policy);
		break;
	case BGPSEC:
		error = certificate_validate_extensions_bgpsec(cert, &ski,
		    &refs, &policy);
		break;
	default:
		/* Validate as a CA */
		error = certificate_validate_extensions_ca(cert, &sia_uris,
		    &refs, &policy);
		break;
	}
	if (error)
		goto revert_cert;

	if (!IS_TA) {
		error = certificate_validate_aia(refs.caIssuers, cert);
		if (error)
			goto revert_uris;
	}

	error = refs_validate_ca(&refs, rpp_parent);
	if (error)
		goto revert_uris;

	if (type == BGPSEC) {
		/* This is an EE, so there's no manifest to process */
		error = handle_bgpsec(cert, ski,
		    x509stack_peek_resources(validation_certstack(state)));
		cert = NULL; /* Ownership stolen at x509stack_push */
		free(ski); /* No need to remember it */
		x509stack_cancel(validation_certstack(state));

		goto revert_refs;
	}

	/*
	 * RFC 6481 section 5: "when the repository publication point contents
	 * are updated, a repository operator cannot assure RPs that the
	 * manifest contents and the repository contents will be precisely
	 * aligned at all times"
	 *
	 * Trying to avoid this issue, download the CA repository and validate
	 * manifest (and its content) again.
	 * 
	 * Avoid to re-download the repo if the mft was fetched with RRDP.
	 */
	mft_retry = true;
	error = use_access_method(&sia_uris, exec_rsync_method,
	    exec_rrdp_method, &mft_retry);
	if (error)
		goto revert_uris;

	do {
		/* Validate the manifest (@mft) pointed by the certificate */
		error = x509stack_push(validation_certstack(state), cert_uri,
		    cert, policy, IS_TA);
		if (error)
			goto revert_uris;

		cert = NULL; /* Ownership stolen */

		error = handle_manifest(sia_uris.mft.uri, &pp);
		if (error == 0 || !mft_retry)
			break;

		pr_info("Retrying repository download to discard 'transient inconsistency' manifest issue (see RFC 6481 section 5) '%s'",
		    uri_get_printable(sia_uris.caRepository.uri));
		error = download_files(sia_uris.caRepository.uri, false, true);
		if (error)
			break;

		/* Cancel stack, reload certificate (no need to revalidate) */
		x509stack_cancel(validation_certstack(state));
		error = certificate_load(cert_uri, &cert);
		if (error)
			goto revert_uris;

		mft_retry = false;
	} while (true);

	if (error) {
		x509stack_cancel(validation_certstack(state));
		goto revert_uris;
	}

	/* -- Validate & traverse the RPP (@pp) described by the manifest -- */
	rpp_traverse(pp);

	rpp_refput(pp);
revert_uris:
	sia_ca_uris_cleanup(&sia_uris);
revert_refs:
	refs_cleanup(&refs);
revert_cert:
	if (cert != NULL)
		X509_free(cert);
revert_fnstack_and_debug:
	fnstack_pop();
	pr_debug("}");
	return error;
}
