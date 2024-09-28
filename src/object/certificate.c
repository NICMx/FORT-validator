#include "object/certificate.h"

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core_names.h>
#endif
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <syslog.h>
#include <time.h>

#include "algorithm.h"
#include "asn1/asn1c/IPAddrBlocks.h"
#include "asn1/decode.h"
#include "cache.h"
#include "common.h"
#include "config.h"
#include "extension.h"
#include "libcrypto_util.h"
#include "log.h"
#include "nid.h"
#include "object/ghostbusters.h"
#include "object/manifest.h"
#include "object/roa.h"
#include "thread_var.h"
#include "types/name.h"
#include "types/path.h"
#include "types/str.h"
#include "types/url.h"

/*
 * The X509V3_EXT_METHOD that references NID_sinfo_access uses the AIA item.
 * The SIA's d2i function, therefore, returns AIAs.
 * They are the same as far as LibreSSL is concerned.
 */
typedef AUTHORITY_INFO_ACCESS SIGNATURE_INFO_ACCESS;

/* Certificates that need to be postponed during a validation cycle. */
SLIST_HEAD(cert_stack, rpki_certificate);

struct ski_arguments {
	X509 *cert;
	OCTET_STRING_t *sid;
};

struct bgpsec_ski {
	X509 *cert;
	unsigned char **ski_data;
};

/* Callback method to fetch repository objects */
typedef int (access_method_exec)(struct sia_uris *);

struct ad_metadata {
	char const *name;
	char const *ia_name;
	char const *type;
	bool required;
};

static const struct ad_metadata CA_ISSUERS = {
	.name = "caIssuers",
	.ia_name = "AIA",
	.type = "rsync",
	.required = true,
};

static const struct ad_metadata SIGNED_OBJECT = {
	.name = "signedObject",
	.ia_name = "SIA",
	.type = "rsync",
	.required = true,
};

static const struct ad_metadata CA_REPOSITORY = {
	.name = "caRepository",
	.ia_name = "SIA",
	.type = "rsync",
	.required = false,
};

static const struct ad_metadata RPKI_NOTIFY = {
	.name = "rpkiNotify",
	.ia_name = "SIA",
	.type = "HTTPS",
	.required = false,
};

static const struct ad_metadata RPKI_MANIFEST = {
	.name = "rpkiManifest",
	.ia_name = "SIA",
	.type = "rsync",
	.required = true,
};

static int
validate_signature_algorithm(X509 *cert)
{
	const ASN1_OBJECT *obj;
	int nid;
	X509_ALGOR_get0(&obj, NULL, NULL, X509_get0_tbs_sigalg(cert));
	nid = OBJ_obj2nid(obj);
	return validate_certificate_signature_algorithm(nid, "Certificate");
}

static int
validate_issuer(struct rpki_certificate *cert)
{
	X509_NAME *issuer;
	struct rfc5280_name *name;
	int error;

	issuer = X509_get_issuer_name(cert->x509);

	if (cert->type != CERTYPE_TA)
		return validate_issuer_name(issuer, cert->parent->x509);

	error = x509_name_decode(issuer, "issuer", &name);
	if (error)
		return error;
	pr_val_debug("Issuer: %s", x509_name_commonName(name));
	x509_name_put(name);

	return 0;
}

/*
 * Compare public keys, call @diff_alg_cb when the algorithm is different, call
 * @diff_pk_cb when the public key is different; return 0 if both are equal.
 */
static int
spki_cmp(X509_PUBKEY *tal_spki, X509_PUBKEY *cert_spki)
{
	ASN1_OBJECT *tal_alg;
	ASN1_OBJECT *cert_alg;

	unsigned char const *tal_spk, *cert_spk;
	int tal_spk_len, cert_spk_len;

	int ok;

	ok = X509_PUBKEY_get0_param(&tal_alg, &tal_spk, &tal_spk_len, NULL,
	    tal_spki);
	if (!ok)
		return val_crypto_err("X509_PUBKEY_get0_param() 1 returned %d", ok);
	ok = X509_PUBKEY_get0_param(&cert_alg, &cert_spk, &cert_spk_len, NULL,
	    cert_spki);
	if (!ok)
		return val_crypto_err("X509_PUBKEY_get0_param() 2 returned %d", ok);

	if (OBJ_cmp(tal_alg, cert_alg) != 0)
		goto root_different_alg_err;
	if (tal_spk_len != cert_spk_len)
		goto root_different_pk_err;
	if (memcmp(tal_spk, cert_spk, cert_spk_len) != 0)
		goto root_different_pk_err;

	return 0;

root_different_alg_err:
	return pr_val_err("TAL's public key algorithm is different than the root certificate's public key algorithm.");
root_different_pk_err:
	return pr_val_err("TAL's public key is different than the root certificate's public key.");
}

/*
 * https://mailarchive.ietf.org/arch/msg/sidrops/mXWbCwh6RO8pAtt7N30Q9m6jUws/
 * Concensus (in mailing list as well as Discord) seems to be "do not check
 * subject name uniqueness."
 */
static int
validate_subject(X509 *cert)
{
	struct rfc5280_name *name;
	int error;

	error = x509_name_decode(X509_get_subject_name(cert), "subject", &name);
	if (error)
		return error;
	pr_val_debug("Subject: %s", x509_name_commonName(name));

	x509_name_put(name);
	return error;
}

static X509_PUBKEY *
decode_spki(struct tal *tal)
{
	X509_PUBKEY *spki;
	unsigned char const *origin, *cursor;
	size_t len;

	fnstack_push(tal_get_file_name(tal));
	tal_get_spki(tal, &origin, &len);
	cursor = origin;
	spki = d2i_X509_PUBKEY(NULL, &cursor, len);

	if (spki == NULL) {
		op_crypto_err("The public key cannot be decoded.");
		goto fail;
	}
	if (cursor != origin + len) {
		X509_PUBKEY_free(spki);
		op_crypto_err("The public key contains trailing garbage.");
		goto fail;
	}

	fnstack_pop();
	return spki;

fail:	fnstack_pop();
	return NULL;
}

static int
validate_spki(X509_PUBKEY *cert_spki)
{
	struct tal *tal;
	X509_PUBKEY *tal_spki;
	int error;

	tal = validation_tal(state_retrieve());
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

	tal_spki = decode_spki(tal);
	if (tal_spki == NULL)
		return -EINVAL;

	error = spki_cmp(tal_spki, cert_spki);

	X509_PUBKEY_free(tal_spki);
	return error;
}

/*
 * RFC 7935 Section 3:
 * "The RSA key pairs used to compute the signatures MUST have a
 * 2048-bit modulus and a public exponent (e) of 65,537."
 */
static int
validate_subject_public_key(X509_PUBKEY *pubkey)
{
#if OPENSSL_VERSION_MAJOR >= 3

	const size_t EXPECTED_BITS = 2048;
	const size_t EXPECTED_EXPONENT = 65537;

	EVP_PKEY *key;
	int key_type;
	size_t bits;
	size_t exponent;

	key = X509_PUBKEY_get0(pubkey);
	if (key == NULL)
		return val_crypto_err("X509_PUBKEY_get0() returned NULL");

	key_type = EVP_PKEY_get_base_id(key);
	if (key_type != EVP_PKEY_RSA && key_type != EVP_PKEY_RSA2)
		return val_crypto_err("The public key type is not RSA: %u",
		    key_type);

	/*
	 * man 7 EVP_PKEY-RSA:
	 *
	 * > "bits" (OSSL_PKEY_PARAM_RSA_BITS) <unsigned integer>
	 * > The value should be the cryptographic length for the RSA
	 * > cryptosystem, in bits.
	 * > "primes" (OSSL_PKEY_PARAM_RSA_PRIMES) <unsigned integer> (...)
	 * > "e" (OSSL_PKEY_PARAM_RSA_E) <unsigned integer> (...)
	 *
	 * I'm having a hard time demonstrating the equality of "cryptographic
	 * length" and "modulus length" using authoritative sources... but I
	 * mean, it makes sense in context:
	 *
	 * Those three arguments from EVP_PKEY-RSA seem to be low-level
	 * equivalents to the ones exposed on `man 1 openssl genpkey`:
	 *
	 * > rsa_keygen_bits:numbits
	 * > The number of bits in the generated key. If not specified 2048 is
	 * > used.
	 * > rsa_keygen_primes:numprimes (...)
	 * > rsa_keygen_pubexp:value (...)
	 *
	 * And https://en.wikipedia.org/wiki/RSA_(cryptosystem):
	 *
	 * > n is used as the modulus for both the public and private keys.
	 * > Its length, usually expressed in bits, is the *key length*.
	 *
	 * So "cryptographic length" equals "key length," and "key length"
	 * equals "modulus length."
	 *
	 * *Shrug*. I'm sorry; it's the best I got.
	 */
	if (!EVP_PKEY_get_size_t_param(key, OSSL_PKEY_PARAM_RSA_BITS, &bits))
		return val_crypto_err("Cannot extract the modulus length from the public key");
	if (bits < EXPECTED_BITS)
		return pr_val_err("Certificate's subjectPublicKey (RSAPublicKey) modulus lengths %zu bits, not %zu bits",
		    bits, EXPECTED_BITS);
	/*
	 * I'm going to be a bit lenient with this, because a small amount of
	 * forward compatibility is bound to be invaluably better than nothing.
	 * (Notice this one's a warning.)
	 */
	if (bits > EXPECTED_BITS)
		pr_val_warn("Certificate's subjectPublicKey (RSAPublicKey) modulus lengths %zu bits, not %zu bits",
		    bits, EXPECTED_BITS);

	/*
	 * man 7 EVP_PKEY-RSA:
	 * "e" (OSSL_PKEY_PARAM_RSA_E) <unsigned integer>
	 * The RSA "e" value. The value may be any odd number greater than or
	 * equal to 65537. The default value is 65537.
	 */
	if (!EVP_PKEY_get_size_t_param(key, OSSL_PKEY_PARAM_RSA_E, &exponent))
		return val_crypto_err("Cannot extract the exponent from the public key");
	if (exponent != EXPECTED_EXPONENT)
		return pr_val_err("Certificate's subjectPublicKey (RSAPublicKey) exponent is %zu, not %zu",
		    exponent, EXPECTED_EXPONENT);

	return 0;

#else /* if OPENSSL_VERSION_MAJOR < 3 */

#define MODULUS 2048
#define EXPONENT "65537"
	EVP_PKEY *pkey;
	const RSA *rsa;
	const BIGNUM *exp;
	char *exp_str;
	int modulus;
	int error;

	pkey = X509_PUBKEY_get0(pubkey);
	if (pkey == NULL)
		return val_crypto_err("The certificate's Subject Public Key is missing or malformed.");

	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa == NULL)
		return val_crypto_err("EVP_PKEY_get0_RSA() returned NULL");

	modulus = RSA_bits(rsa);
	if (modulus < MODULUS)
		return pr_val_err("Certificate's subjectPublicKey (RSAPublicKey) modulus is %d bits, not %d bits.",
		    modulus, MODULUS);
	if (modulus > MODULUS)
		pr_val_warn("Certificate's subjectPublicKey (RSAPublicKey) modulus lengths %d bits, not %d bits",
		    modulus, MODULUS);

	RSA_get0_key(rsa, NULL, &exp, NULL);
	if (exp == NULL)
		return pr_val_err("Certificate's subjectPublicKey (RSAPublicKey) exponent isn't set, must be "
		    EXPONENT " bits.");

	exp_str = BN_bn2dec(exp);
	if (exp_str == NULL)
		return val_crypto_err("Couldn't get subjectPublicKey exponent string");

	if (strcmp(EXPONENT, exp_str) != 0) {
		error = pr_val_err("Certificate's subjectPublicKey (RSAPublicKey) exponent is %s, must be "
		    EXPONENT " bits.", exp_str);
		free(exp_str);
		return error;
	}
	free(exp_str);

	return 0;
#undef EXPONENT
#undef MODULUS

#endif /* OPENSSL_VERSION_MAJOR */
}

static int
validate_public_key(X509 *cert, enum cert_type type)
{
	X509_PUBKEY *pubkey;
	EVP_PKEY *evppkey;
	X509_ALGOR *pa;
	int ok;
	int error;

	/* Reminder: X509_PUBKEY is the same as SubjectPublicKeyInfo. */
	pubkey = X509_get_X509_PUBKEY(cert);
	if (pubkey == NULL)
		return val_crypto_err("X509_get_X509_PUBKEY() returned NULL");

	ok = X509_PUBKEY_get0_param(NULL, NULL, NULL, &pa, pubkey);
	if (!ok)
		return val_crypto_err("X509_PUBKEY_get0_param() returned %d", ok);

	if (type == CERTYPE_BGPSEC)
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

	if (type == CERTYPE_TA) {
		error = validate_spki(pubkey);
		if (error)
			return error;
		if ((evppkey = X509_get0_pubkey(cert)) == NULL)
			return val_crypto_err("X509_get0_pubkey() returned NULL");
		if (X509_verify(cert, evppkey) != 1)
			return -EINVAL;
	}

	return 0;
}

int
certificate_validate_rfc6487(struct rpki_certificate *cert)
{
	int error;

	/*
	 * I'm simply assuming that libcrypto implements RFC 5280. (I mean, it's
	 * not really stated anywhere AFAIK, but since OpenSSL is supposedly the
	 * quintessential crypto lib implementation, and RFC 5280 is supposedly
	 * the generic certificate RFC, it's fair to say it does a well enough
	 * job for all practical purposes.)
	 */

	/* rfc6487#section-4.1 */
	if (X509_get_version(cert->x509) != 2)
		return pr_val_err("Certificate version is not v3.");

	/* rfc6487#section-4.2 */
	/* <Redacted> */

	/* rfc6487#section-4.3 */
	error = validate_signature_algorithm(cert->x509);
	if (error)
		return error;

	/* rfc6487#section-4.4 */
	error = validate_issuer(cert);
	if (error)
		return error;

	/*
	 * rfc6487#section-4.5
	 *
	 * "An issuer SHOULD use a different subject name if the subject's
	 * key pair has changed" (it's a SHOULD, so [for now] avoid validation)
	 */
	error = validate_subject(cert->x509);
	if (error)
		return error;

	/* rfc6487#section-4.6 */
	/* libcrypto already does this. */

	/* rfc6487#section-4.7 */
	/* Fragment of rfc8630#section-2.3 */
	error = validate_public_key(cert->x509, cert->type);
	if (error)
		return error;

	/* We'll validate extensions later. */
	return 0;
}

struct progress {
	size_t offset;
	size_t remaining;
};

/* Skip the "T" part of a TLV. */
static int
skip_t(ANY_t *content, struct progress *p, unsigned int tag)
{
	/* These errors happen when the object is not DER-encoded */

	if (content->buf[p->offset] != tag)
		return pr_val_err("Expected tag 0x%x, got 0x%x.",
		    tag, content->buf[p->offset]);
	if (p->remaining == 0)
		return pr_val_err("Buffer seems truncated.");

	p->offset++;
	p->remaining--;
	return 0;
}

/* Skip the "TL" part of a TLV. */
static int
skip_tl(ANY_t *content, struct progress *p, unsigned int tag)
{
	ssize_t len_len; /* Length of the length field */
	ber_tlv_len_t value_len; /* Length of the value */

	if (skip_t(content, p, tag) != 0)
		return -EINVAL;

	len_len = ber_fetch_length(true, &content->buf[p->offset], p->remaining,
	    &value_len);
	if (len_len == -1)
		return pr_val_err("Could not decipher length (Unknown cause).");
	if (len_len == 0)
		return pr_val_err("Buffer seems truncated.");

	p->offset += len_len;
	p->remaining -= len_len;
	return 0;
}

static int
skip_tlv(ANY_t *content, struct progress *p, unsigned int tag)
{
	int is_constructed;
	int skip;

	is_constructed = BER_TLV_CONSTRUCTED(&content->buf[p->offset]);

	if (skip_t(content, p, tag) != 0)
		return -EINVAL;

	skip = ber_skip_length(NULL, is_constructed, &content->buf[p->offset],
	    p->remaining);
	if (skip == -1)
		return pr_val_err("Could not skip length (Unknown cause).");
	if (skip == 0)
		return pr_val_err("Buffer seems truncated.");

	p->offset += skip;
	p->remaining -= skip;
	return 0;
}

/* A structure that points to the LV part of a signedAttrs TLV. */
struct encoded_signedAttrs {
	const uint8_t *buffer;
	ber_tlv_len_t size;
};

static int
find_signedAttrs(ANY_t *signedData, struct encoded_signedAttrs *result)
{
	static const unsigned int INTEGER_TAG = 0x02;
	static const unsigned int SEQUENCE_TAG = 0x30;
	static const unsigned int SET_TAG = 0x31;

	struct progress p;
	ssize_t len_len;

	/* Reference: rfc5652-12.1.asn1 */

	p.offset = 0;
	p.remaining = signedData->size;

	/* SignedData: SEQUENCE */
	if (skip_tl(signedData, &p, SEQUENCE_TAG) != 0)
		return -EINVAL;

	/* SignedData.version: CMSVersion -> INTEGER */
	if (skip_tlv(signedData, &p, INTEGER_TAG) != 0)
		return -EINVAL;
	/* SignedData.digestAlgorithms: DigestAlgorithmIdentifiers -> SET */
	if (skip_tlv(signedData, &p, SET_TAG) != 0)
		return -EINVAL;
	/* SignedData.encapContentInfo: EncapsulatedContentInfo -> SEQUENCE */
	if (skip_tlv(signedData, &p, SEQUENCE_TAG) != 0)
		return -EINVAL;
	/* SignedData.certificates: CertificateSet -> SET */
	if (skip_tlv(signedData, &p, 0xA0) != 0)
		return -EINVAL;
	/* SignedData.signerInfos: SignerInfos -> SET OF SEQUENCE */
	if (skip_tl(signedData, &p, SET_TAG) != 0)
		return -EINVAL;
	if (skip_tl(signedData, &p, SEQUENCE_TAG) != 0)
		return -EINVAL;

	/* SignedData.signerInfos.version: CMSVersion -> INTEGER */
	if (skip_tlv(signedData, &p, INTEGER_TAG) != 0)
		return -EINVAL;
	/*
	 * SignedData.signerInfos.sid: SignerIdentifier -> CHOICE -> always
	 * subjectKeyIdentifier, which is a [0].
	 */
	if (skip_tlv(signedData, &p, 0x80) != 0)
		return -EINVAL;
	/* SignedData.signerInfos.digestAlgorithm: DigestAlgorithmIdentifier
	 * -> AlgorithmIdentifier -> SEQUENCE */
	if (skip_tlv(signedData, &p, SEQUENCE_TAG) != 0)
		return -EINVAL;

	/* SignedData.signerInfos.signedAttrs: SignedAttributes -> SET */
	/* We will need to replace the tag 0xA0 with 0x31, so skip it as well */
	if (skip_t(signedData, &p, 0xA0) != 0)
		return -EINVAL;

	result->buffer = &signedData->buf[p.offset];
	len_len = ber_fetch_length(true, result->buffer,
	    p.remaining, &result->size);
	if (len_len == -1)
		return pr_val_err("Could not decipher length (Unknown cause.)");
	if (len_len == 0)
		return pr_val_err("Buffer seems truncated.");
	result->size += len_len;
	return 0;
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
		return val_crypto_err("Certificate seems to lack a public key");

	/* Create the Message Digest Context */
	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
		return val_crypto_err("EVP_MD_CTX_create() error");

	if (1 != EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL,
	    X509_PUBKEY_get0(public_key))) {
		error = val_crypto_err("EVP_DigestVerifyInit() error");
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
	 * encoding function that crashes everything. It's caused by undefined
	 * behavior that triggers who knows where.
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

	error = find_signedAttrs(signedData, &signedAttrs);
	if (error)
		goto end;

	error = EVP_DigestVerifyUpdate(ctx, &EXPLICIT_SET_OF_TAG,
	    sizeof(EXPLICIT_SET_OF_TAG));
	if (1 != error) {
		error = val_crypto_err("EVP_DigestVerifyInit() error");
		goto end;
	}

	error = EVP_DigestVerifyUpdate(ctx, signedAttrs.buffer,
	    signedAttrs.size);
	if (1 != error) {
		error = val_crypto_err("EVP_DigestVerifyInit() error");
		goto end;
	}

	if (1 != EVP_DigestVerifyFinal(ctx, signature->buf, signature->size)) {
		error = val_crypto_err("Signed Object's signature is invalid");
		goto end;
	}

	error = 0;

end:
	EVP_MD_CTX_free(ctx);
	return error;
}

static X509 *
certificate_load(char const *path)
{
	X509 *cert = NULL;
	BIO *bio;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL) {
		val_crypto_err("BIO_new(BIO_s_file()) returned NULL");
		return NULL;
	}
	if (BIO_read_filename(bio, path) <= 0) {
		val_crypto_err("Error reading certificate");
		goto end;
	}

	cert = d2i_X509_bio(bio, NULL);
	if (cert == NULL) {
		val_crypto_err("Error parsing certificate");
		goto end;
	}

end:	BIO_free(bio);
	return cert;
}

static void
certificate_stack_push(struct cert_stack *stack, struct cache_mapping *map,
    struct rpki_certificate *parent)
{
	struct rpki_certificate *cert;

	cert = pzalloc(sizeof(*cert));
	cert->refcount++;

	map_copy(&cert->map, map);

	cert->parent = parent;
	parent->refcount++;

	cert->rpp.ancestors = X509_chain_up_ref(parent->rpp.ancestors);
	if (!cert->rpp.ancestors)
		goto fail;
	if (sk_X509_push(cert->rpp.ancestors, parent->x509) <= 0)
		goto fail;
	if (!X509_up_ref(parent->x509))
		goto fail;

	SLIST_INSERT_HEAD(stack, cert, lh);
	return;

fail:	rpki_certificate_free(cert);
}

void
rpki_certificate_init_ee(struct rpki_certificate *ee,
    struct rpki_certificate *parent, bool force_inherit)
{
	memset(ee, 0, sizeof(*ee));
	ee->type = CERTYPE_EE;
	ee->policy = RPKI_POLICY_RFC6484;
	ee->resources = resources_create(RPKI_POLICY_RFC6484, force_inherit);
	ee->parent = parent;
	ee->refcount = 1;
}

void
rpki_certificate_cleanup(struct rpki_certificate *cert)
{
	map_cleanup(&cert->map);
	if (cert->x509 != NULL)
		X509_free(cert->x509);
	resources_destroy(cert->resources);
	sias_cleanup(&cert->sias);
	// XXX Recursive. Try refcounting the resources.
	rpki_certificate_free(cert->parent);
	rpp_cleanup(&cert->rpp);
}

void
rpki_certificate_free(struct rpki_certificate *cert)
{
	cert->refcount--;
	if (cert->refcount == 0) {
		rpki_certificate_cleanup(cert);
		free(cert);
	}
}

static void
pr_debug_x509_dates(X509 *x509)
{
	char *nb, *na;

	nb = asn1time2str(X509_get0_notBefore(x509));
	na = asn1time2str(X509_get0_notAfter(x509));

	pr_val_debug("Valid range: [%s, %s]", nb, na);

	free(nb);
	free(na);
}

static void
complain_crl_stale(X509_CRL *crl)
{
	char *lu;
	char *nu;

	lu = asn1time2str(X509_CRL_get0_lastUpdate(crl));
	nu = asn1time2str(X509_CRL_get0_nextUpdate(crl));

	pr_val_err("CRL is stale/expired. (lastUpdate:%s, nextUpdate:%s)",
	    lu, nu);

	free(lu);
	free(nu);
}

int
certificate_validate_chain(struct rpki_certificate *cert)
{
	/* Reference: openbsd/src/usr.bin/openssl/verify.c */

	X509_STORE_CTX *ctx;
	STACK_OF(X509_CRL) *crls;
	int ok;
	int error;

	if (cert->type == CERTYPE_TA)
		return 0; /* No chain to validate. */

	ctx = X509_STORE_CTX_new();
	if (ctx == NULL) {
		val_crypto_err("X509_STORE_CTX_new() returned NULL");
		return -EINVAL;
	}

	/* Returns 0 or 1 , all callers test ! only. */
	ok = X509_STORE_CTX_init(ctx, validation_store(state_retrieve()),
	    cert->x509, NULL);
	if (!ok) {
		val_crypto_err("X509_STORE_CTX_init() returned %d", ok);
		goto abort;
	}

	X509_STORE_CTX_trusted_stack(ctx, cert->rpp.ancestors);

	crls = sk_X509_CRL_new_null();
	if (!crls)
		enomem_panic();
	if (sk_X509_CRL_push(crls, cert->rpp.crl.obj) != 1) {
		// XXX
	}
	// XXX These CRLs will only be used if CRL verification is enabled in
	// the associated X509_VERIFY_PARAM structure.
	X509_STORE_CTX_set0_crls(ctx, crls); // XXX needs free
	// sk_X509_CRL_pop_free(cert->crl.stack, X509_CRL_free);

	if (log_val_enabled(LOG_DEBUG))
		pr_debug_x509_dates(cert->x509);

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
		 * Do not use val_crypto_err() here; for some reason the proper
		 * error code is stored in the context.
		 */
		error = X509_STORE_CTX_get_error(ctx);
		if (error == X509_V_ERR_CRL_HAS_EXPIRED)
			complain_crl_stale(cert->rpp.crl.obj);
		else if (error)
			pr_val_err("Certificate validation failed: %s",
			    X509_verify_cert_error_string(error));
		else
			/*
			 * ...But don't trust X509_STORE_CTX_get_error() either.
			 * That said, there's not much to do about !error,
			 * so hope for the best.
			 */
			val_crypto_err("Certificate validation failed: %d", ok);
		goto abort;
	}

	X509_STORE_CTX_free(ctx);
	return 0;

abort:
	X509_STORE_CTX_free(ctx);
	return -EINVAL;
}

static int
handle_ip_extension(struct rpki_certificate *cert, X509_EXTENSION *ext)
{
	ASN1_OCTET_STRING *string;
	struct IPAddrBlocks *blocks;
	OCTET_STRING_t *family;
	int i;
	int error;

	string = X509_EXTENSION_get_data(ext);
	error = asn1_decode(string->data, string->length, &asn_DEF_IPAddrBlocks,
	    (void **) &blocks, true);
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
			error = pr_val_err("First IP address block listed is not v4.");
			goto end;
		}
		family = &blocks->list.array[1]->addressFamily;
		if (get_addr_family(family) != AF_INET6) {
			error = pr_val_err("Second IP address block listed is not v6.");
			goto end;
		}
		break;
	default:
		error = pr_val_err("Got %d IP address blocks Expected; 1 or 2 expected.",
		    blocks->list.count);
		goto end;
	}

	for (i = 0; i < blocks->list.count && !error; i++)
		error = resources_add_ip(cert->resources,
		    cert->parent->resources,
		    blocks->list.array[i]);

end:
	ASN_STRUCT_FREE(asn_DEF_IPAddrBlocks, blocks);
	return error;
}

static int
handle_asn_extension(struct rpki_certificate *cert, X509_EXTENSION *ext)
{
	ASN1_OCTET_STRING *string;
	struct ASIdentifiers *ids;
	int error;

	string = X509_EXTENSION_get_data(ext);
	error = asn1_decode(string->data, string->length,
	    &asn_DEF_ASIdentifiers, (void **) &ids, true);
	if (error)
		return error;

	error = resources_add_asn(cert->resources, cert->parent->resources,
	    ids, cert->type != CERTYPE_BGPSEC);

	ASN_STRUCT_FREE(asn_DEF_ASIdentifiers, ids);
	return error;
}

static int
__certificate_get_resources(struct rpki_certificate *cert,
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

	for (i = 0; i < X509_get_ext_count(cert->x509); i++) {
		ext = X509_get_ext(cert->x509, i);
		nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));

		if (nid == addr_nid) {
			if (ip_ext_found)
				return pr_val_err("Multiple IP extensions found.");
			if (!X509_EXTENSION_get_critical(ext))
				return pr_val_err("The IP extension is not marked as critical.");

			ip_ext_found = true;

			error = handle_ip_extension(cert, ext);
			if (error)
				return error;

		} else if (nid == asn_nid) {
			if (asn_ext_found)
				return pr_val_err("Multiple AS extensions found.");
			if (!X509_EXTENSION_get_critical(ext))
				return pr_val_err("The AS extension is not marked as critical.");

			asn_ext_found = true;

			error = handle_asn_extension(cert, ext);
			if (error)
				return error;

		} else if (nid == bad_addr_nid) {
			return pr_val_err("Certificate has an RFC%s policy, but contains an RFC%s IP extension.",
			    policy_rfc, bad_ext_rfc);
		} else if (nid == bad_asn_nid) {
			return pr_val_err("Certificate has an RFC%s policy, but contains an RFC%s ASN extension.",
			    policy_rfc, bad_ext_rfc);
		}
	}

	if (!ip_ext_found && !asn_ext_found)
		return pr_val_err("Certificate lacks both IP and AS extension.");

	return 0;
}

/* Copies the resources from @cert to @resources. */
int
certificate_get_resources(struct rpki_certificate *cert)
{
	switch (cert->policy) {
	case RPKI_POLICY_RFC6484:
		return __certificate_get_resources(cert,
		    NID_sbgp_ipAddrBlock, NID_sbgp_autonomousSysNum,
		    nid_ipAddrBlocksv2(), nid_autonomousSysIdsv2(),
		    "6484", "8360");
	case RPKI_POLICY_RFC8360:
		return __certificate_get_resources(cert,
		    nid_ipAddrBlocksv2(), nid_autonomousSysIdsv2(),
		    NID_sbgp_ipAddrBlock, NID_sbgp_autonomousSysNum,
		    "8360", "6484");
	}

	pr_crit("Unknown policy: %u", cert->policy);
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

static void
handle_rpkiManifest(char *uri, void *arg)
{
	struct sia_uris *uris = arg;

	pr_val_debug("rpkiManifest: %s", uri);

	if (uris->rpkiManifest != NULL) {
		pr_val_warn("Ignoring additional rpkiManifest: %s", uri);
		free(uri);
	} else {
		uris->rpkiManifest = uri;
	}
}

static void
handle_caRepository(char *uri, void *arg)
{
	struct sia_uris *uris = arg;

	pr_val_debug("caRepository: %s", uri);

	if (uris->caRepository != NULL) {
		pr_val_warn("Ignoring additional caRepository: %s", uri);
		free(uri);
	} else {
		uris->caRepository = uri;
	}
}

static void
handle_rpkiNotify(char *uri, void *arg)
{
	struct sia_uris *uris = arg;

	pr_val_debug("rpkiNotify: %s", uri);

	if (uris->rpkiNotify != NULL) {
		pr_val_warn("Ignoring additional rpkiNotify: %s", uri);
		free(uri);
	} else {
		uris->rpkiNotify = uri;
	}
}

static void
handle_signedObject(char *uri, void *arg)
{
	struct sia_uris *sias = arg;
	pr_val_debug("signedObject: %s", uri);
	sias->signedObject = uri;
}

static int
handle_bc(void *ext, void *arg)
{
	BASIC_CONSTRAINTS *bc = ext;

	/*
	 * 'The issuer determines whether the "cA" boolean is set.'
	 * ................................. Uh-huh. So nothing then.
	 * Well, libcrypto should do the RFC 5280 thing with it anyway.
	 */

	return (bc->pathlen == NULL)
	    ? 0
	    : pr_val_err("%s extension contains a Path Length Constraint.",
	          ext_bc()->name);
}

static int
handle_ski_ca(void *ext, void *arg)
{
	return validate_public_key_hash(arg, ext, "SKI");
}

static int
handle_ski_ee(void *ext, void *arg)
{
	ASN1_OCTET_STRING *ski = ext;
	struct ski_arguments *args = arg;
	OCTET_STRING_t *sid;
	int error;

	error = validate_public_key_hash(args->cert, ski, "SKI");
	if (error)
		return error;

	/* rfc6488#section-2.1.6.2 */
	/* rfc6488#section-3.1.c 2/2 */
	sid = args->sid;
	if (ski->length != sid->size
	    || memcmp(ski->data, sid->buf, sid->size) != 0) {
		return pr_val_err("The EE certificate's subjectKeyIdentifier does not equal the Signed Object's sid.");
	}

	return 0;
}

static int
handle_aki_ta(void *ext, void *arg)
{
	struct AUTHORITY_KEYID_st *aki = ext;
	ASN1_OCTET_STRING *ski;
	int error;

	if (aki->keyid == NULL) {
		return pr_val_err("The '%s' extension lacks a keyIdentifier.",
		    ext_aki()->name);
	}

	ski = X509_get_ext_d2i(arg, NID_subject_key_identifier, NULL, NULL);
	if (ski == NULL) {
		pr_val_err("Certificate lacks the '%s' extension.",
		    ext_ski()->name);
		return -ESRCH;
	}

	error = (ASN1_OCTET_STRING_cmp(aki->keyid, ski) != 0)
	      ? pr_val_err("The '%s' does not equal the '%s'.",
	                   ext_aki()->name, ext_ski()->name)
	      : 0;

	ASN1_BIT_STRING_free(ski);
	return error;
}

static int
handle_ku(ASN1_BIT_STRING *ku, unsigned char byte1)
{
	/*
	 * About the key usage string: At time of writing, it's 9 bits long.
	 * But zeroized rightmost bits can be omitted.
	 * This implementation assumes that the ninth bit should always be zero.
	 */

	unsigned char data[2];

	if (ku->length != 2 && ku->length != 1) {
		return pr_val_err("Bogus %s length: %d",
		    ext_ku()->name, ku->length);
	}

	memset(data, 0, sizeof(data));
	memcpy(data, ku->data, ku->length);

	if (data[0] != byte1 || data[1] != 0) {
		return pr_val_err("Illegal key usage flag string: %d%d%d%d%d%d%d%d%d",
		    !!(data[0] & 0x80u), !!(data[0] & 0x40u),
		    !!(data[0] & 0x20u), !!(data[0] & 0x10u),
		    !!(data[0] & 0x08u), !!(data[0] & 0x04u),
		    !!(data[0] & 0x02u), !!(data[0] & 0x01u),
		    !!(data[1] & 0x80u));
	}

	return 0;
}

static int
handle_ku_ca(void *ext, void *arg)
{
	return handle_ku(ext, 0x06);
}

static int
handle_ku_ee(void *ext, void *arg)
{
	return handle_ku(ext, 0x80);
}

static int
handle_cdp(void *ext, void *arg)
{
	STACK_OF(DIST_POINT) *crldp = ext;
	struct sia_uris *sias = arg;
	DIST_POINT *dp;
	GENERAL_NAMES *names;
	GENERAL_NAME *name;
	ASN1_IA5STRING *str;
	int i;
	int type;
	char const *error_msg;

	if (sk_DIST_POINT_num(crldp) != 1) {
		return pr_val_err("The %s extension has %d distribution points. (1 expected)",
		    ext_cdp()->name, sk_DIST_POINT_num(crldp));
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
		str = GENERAL_NAME_get0_value(name, &type);
		if (type == GEN_URI && is_rsync(str)) {
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
			return ia5s2string(str, &sias->crldp);
		}
	}

	error_msg = "lacks an RSYNC URI";

dist_point_error:
	return pr_val_err("The %s extension's distribution point %s.",
	    ext_cdp()->name, error_msg);
}

/*
 * Create @map from the @ad
 */
static int
ad2uri(char **uri, ACCESS_DESCRIPTION *ad)
{
	ASN1_STRING *asn1str;
	int ptype;

	asn1str = GENERAL_NAME_get0_value(ad->location, &ptype);

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
	 * would be a titanic pain. So this is what I'm committing to.
	 */
	if (ptype != GEN_URI) {
		pr_val_err("Unknown GENERAL_NAME type: %d", ptype);
		return ENOTSUPPORTED;
	}

	/*
	 * GEN_URI signals an IA5String.
	 * IA5String is a subset of ASCII, so this cast is safe.
	 * No guarantees of a NULL chara though, which is why we need a dup.
	 *
	 * TODO (testers) According to RFC 5280, accessLocation can be an IRI
	 * somehow converted into URI form. I don't think that's an issue
	 * because the RSYNC clone operation should not have performed the
	 * conversion, so we should be looking at precisely the IA5String
	 * directory our g2l version of @asn1_string should contain.
	 * But ask the testers to keep an eye on it anyway.
	 *
	 * XXX There used to be a map_create() here. Make sure validations are
	 * restored somewhere:
	 * 1. ascii
	 * 2. "rsync://" or "https://" prefix (ENOTRSYNC, ENOTHTTPS)
	 * 3. URL normalization
	 */
	*uri = pstrndup((char const *)ASN1_STRING_get0_data(asn1str),
	    ASN1_STRING_length(asn1str));
	return 0;
}

/*
 * The RFC does not explain AD validation very well. This is personal
 * interpretation, influenced by Tim Bruijnzeels's response
 * (https://mailarchive.ietf.org/arch/msg/sidr/4ycmff9jEU4VU9gGK5RyhZ7JYsQ)
 * (I'm being a bit more lax than he suggested.)
 *
 * 1. The NID (@nid) can be found more than once.
 * 2. All access descriptions that match the NID must be URLs.
 * 3. Depending on meta->required, zero or one of those matches will be an URL
 *    of the meta->type we're expecting.
 *    (I would have gone with "at least zero of those matches", but I don't know
 *    what to do with the other ones.)
 * 4. Other access descriptions that do not match the NID are allowed and
 *    supposed to be ignored.
 * 5. Other access descriptions that match the NID but do not have recognized
 *    URLs are also allowed, and also supposed to be ignored.
 *
 * cb() always steals ownership of the URL string.
 *
 * TODO (test) is this tested somewhere?
 */
static int
handle_ad(int nid, struct ad_metadata const *meta, SIGNATURE_INFO_ACCESS *ia,
    void (*cb)(char *, void *), void *arg)
{
	ACCESS_DESCRIPTION *ad;
	char *uri;
	bool found;
	unsigned int i;
	int error;

	found = false;
	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(ia, i);
		if (OBJ_obj2nid(ad->method) == nid) {
			error = ad2uri(&uri, ad);
			switch (error) {
			case 0:
				break;
			case ENOTSUPPORTED:
				continue;
			default:
				return error;
			}

			if (found) {
				free(uri);
				return pr_val_err("Extension '%s' has multiple '%s' %s URIs.",
				    meta->ia_name, meta->name, meta->type);
			}

			cb(uri, arg); /* Ownership of uri stolen */
			found = true;
		}
	}

	if (meta->required && !found) {
		pr_val_err("Extension '%s' lacks a '%s' valid %s URI.",
		    meta->ia_name, meta->name, meta->type);
		return -ESRCH;
	}

	return 0;
}

static void
handle_caIssuers(char *uri, void *arg)
{
	struct sia_uris *sias = arg;
	/*
	 * Bringing the parent certificate's URI all the way
	 * over here is too much trouble, so do the handle_cdp()
	 * hack.
	 *
	 * XXX Uh... it's extremely easy now.
	 */
	sias->caIssuers = uri;
}

static int
handle_aia(void *ext, void *arg)
{
	return handle_ad(NID_ad_ca_issuers, &CA_ISSUERS, ext,
	    handle_caIssuers, arg);
}

static int
handle_sia_ca(void *ext, void *arg)
{
	SIGNATURE_INFO_ACCESS *sia = ext;
	struct sia_uris *uris = arg;
	int error;

	/* rsync */
	error = handle_ad(NID_caRepository, &CA_REPOSITORY, sia,
	    handle_caRepository, uris);
	if (error)
		return error;

	/* RRDP */
	error = handle_ad(nid_ad_notify(), &RPKI_NOTIFY, sia,
	    handle_rpkiNotify, uris);
	if (error)
		return error;

	/* Manifest */
	return handle_ad(nid_ad_mft(), &RPKI_MANIFEST, sia,
	    handle_rpkiManifest, uris);
}

static int
handle_sia_ee(void *ext, void *arg)
{
	return handle_ad(nid_ad_so(), &SIGNED_OBJECT, ext,
	    handle_signedObject, arg);
}

static int
handle_cp(void *ext, void *arg)
{
	CERTIFICATEPOLICIES *cp = ext;
	enum rpki_policy *policy = arg;
	POLICYINFO *pi;
	POLICYQUALINFO *pqi;
	int nid_cp, nid_qt_cps, pqi_num;

	if (sk_POLICYINFO_num(cp) != 1) {
		return pr_val_err("The %s extension has %d policy information's. (1 expected)",
		    ext_cp()->name, sk_POLICYINFO_num(cp));
	}

	/* rfc7318#section-2 and consider rfc8360#section-4.2.1 */
	pi = sk_POLICYINFO_value(cp, 0);
	nid_cp = OBJ_obj2nid(pi->policyid);
	if (nid_cp == nid_certPolicyRpki()) {
		if (policy != NULL)
			*policy = RPKI_POLICY_RFC6484;
	} else if (nid_cp == nid_certPolicyRpkiV2()) {
		pr_val_debug("Found RFC8360 policy!");
		if (policy != NULL)
			*policy = RPKI_POLICY_RFC8360;
	} else {
		return pr_val_err("Invalid certificate policy OID, isn't 'id-cp-ipAddr-asNumber' nor 'id-cp-ipAddr-asNumber-v2'");
	}

	/* Exactly one policy qualifier MAY be included (so none is also valid) */
	if (pi->qualifiers == NULL)
		return 0;

	pqi_num = sk_POLICYQUALINFO_num(pi->qualifiers);
	if (pqi_num == 0)
		return 0;
	if (pqi_num != 1) {
		return pr_val_err("The %s extension has %d policy qualifiers. (none or only 1 expected)",
		    ext_cp()->name, pqi_num);
	}

	pqi = sk_POLICYQUALINFO_value(pi->qualifiers, 0);
	nid_qt_cps = OBJ_obj2nid(pqi->pqualid);
	if (nid_qt_cps != NID_id_qt_cps)
		return pr_val_err("Policy qualifier ID isn't Certification Practice Statement (CPS)");

	return 0;
}

/* Validates the certificate extensions, Trust Anchor style. */
static int
validate_ta_extensions(struct rpki_certificate *cert)
{
	struct extension_handler handlers[] = {
	   /* ext        reqd   handler        arg           */
	    { ext_bc(),  true,  handle_bc,                    },
	    { ext_ski(), true,  handle_ski_ca, cert->x509     },
	    { ext_aki(), false, handle_aki_ta, cert->x509     },
	    { ext_ku(),  true,  handle_ku_ca,                 },
	    { ext_sia(), true,  handle_sia_ca, &cert->sias    },
	    { ext_cp(),  true,  handle_cp,     &cert->policy  },
	    /* These are handled by certificate_get_resources(). */
	    { ext_ir(),  false,                               },
	    { ext_ar(),  false,                               },
	    { ext_ir2(), false,                               },
	    { ext_ar2(), false,                               },
	    { NULL },
	};

	return handle_extensions(handlers, X509_get0_extensions(cert->x509));
}

/*
 * Validates the certificate extensions, (intermediate) Certificate Authority
 * style.
 *
 * Also initializes the fourth argument with the references found in the
 * extensions.
 */
static int
validate_ca_extensions(struct rpki_certificate *cert)
{
	struct extension_handler handlers[] = {
	   /* ext        reqd   handler        arg           */
	    { ext_bc(),  true,  handle_bc,                    },
	    { ext_ski(), true,  handle_ski_ca, cert->x509     },
	    { ext_aki(), true,  handle_aki,                   },
	    { ext_ku(),  true,  handle_ku_ca,                 },
	    { ext_cdp(), true,  handle_cdp,    &cert->sias    },
	    { ext_aia(), true,  handle_aia,    &cert->sias    },
	    { ext_sia(), true,  handle_sia_ca, &cert->sias    },
	    { ext_cp(),  true,  handle_cp,     &cert->policy  },
	    /* These are handled by certificate_get_resources(). */
	    { ext_ir(),  false,                               },
	    { ext_ar(),  false,                               },
	    { ext_ir2(), false,                               },
	    { ext_ar2(), false,                               },
	    { NULL },
	};
	int error;

	error = handle_extensions(handlers, X509_get0_extensions(cert->x509));
	if (error)
		return error;
	error = certificate_validate_aia(cert);
	if (error)
		return error;
	return validate_cdp(&cert->sias, cert->rpp.crl.map->url);
}

int
certificate_validate_extensions_ee(struct rpki_certificate *cert,
    OCTET_STRING_t *sid)
{
	struct ski_arguments ski_args;
	struct extension_handler handlers[] = {
	   /* ext        reqd   handler        arg           */
	    { ext_ski(), true,  handle_ski_ee, &ski_args      },
	    { ext_aki(), true,  handle_aki,                   },
	    { ext_ku(),  true,  handle_ku_ee,                 },
	    { ext_cdp(), true,  handle_cdp,    &cert->sias    },
	    { ext_aia(), true,  handle_aia,    &cert->sias    },
	    { ext_sia(), true,  handle_sia_ee, &cert->sias    },
	    { ext_cp(),  true,  handle_cp,     &cert->policy  },
	    { ext_ir(),  false,                               },
	    { ext_ar(),  false,                               },
	    { ext_ir2(), false,                               },
	    { ext_ar2(), false,                               },
	    { NULL },
	};

	ski_args.cert = cert->x509;
	ski_args.sid = sid;

	return handle_extensions(handlers, X509_get0_extensions(cert->x509));
}

int
certificate_validate_extensions_bgpsec(void)
{
	return 0; /* TODO (#58) */
}

static bool
has_bgpsec_router_eku(X509 *cert)
{
	EXTENDED_KEY_USAGE *eku;
	int i;
	int nid;

	eku = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
	if (eku == NULL)
		return false;

	/* RFC 8209#section-3.1.3.2: Unknown KeyPurposeIds are allowed. */
	for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
		nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i));
		if (nid == nid_bgpsecRouter()) {
			EXTENDED_KEY_USAGE_free(eku);
			return true;
		}
	}

	EXTENDED_KEY_USAGE_free(eku);
	return false;
}

/*
 * Assumption: Meant to be used exclusively in the context of parsing a .cer
 * certificate.
 */
static enum cert_type
get_certificate_type(struct rpki_certificate *cert)
{
	if (cert->rpp.ancestors == NULL)
		return CERTYPE_TA;

	if (X509_check_purpose(cert->x509, -1, -1) <= 0)
		return CERTYPE_UNKNOWN;

	if (X509_check_ca(cert->x509) == 1)
		return CERTYPE_CA;

	if (has_bgpsec_router_eku(cert->x509))
		return CERTYPE_BGPSEC;

	return CERTYPE_UNKNOWN;
}

int
certificate_validate_aia(struct rpki_certificate *cert)
{
	/*
	 * FIXME Compare the AIA to the parent's URI.
	 * We're currently not recording the URI, so this can't be solved until
	 * the #78 refactor.
	 */
	return 0;
}

static int
init_resources(struct rpki_certificate *cert)
{
	int error;

	cert->resources = resources_create(cert->policy, false);

	error = certificate_get_resources(cert);
	if (error)
		return error;

	/*
	 * rfc8630#section-2.3
	 * "The INR extension(s) of this TA MUST contain a non-empty set of
	 * number resources."
	 * The "It MUST NOT use the "inherit" form of the INR extension(s)"
	 * part is already handled in certificate_get_resources().
	 */
	if (cert->type == CERTYPE_TA && resources_empty(cert->resources))
		return pr_val_err("Trust Anchor certificate does not define any number resources.");

	return 0;
}

static int
certificate_validate(struct rpki_certificate *cert)
{
	int error;

	if (sk_X509_num(cert->rpp.ancestors) >= config_get_max_cert_depth())
		return pr_val_err("Certificate chain maximum depth exceeded.");

	fnstack_push_map(&cert->map);

	cert->x509 = certificate_load(cert->map.path);
	if (!cert->x509)
		return -EINVAL;
	cert->type = get_certificate_type(cert);

	error = certificate_validate_chain(cert);
	if (error)
		goto end;

	switch (cert->type) {
	case CERTYPE_TA:
		break;
	case CERTYPE_CA:
		pr_val_debug("Type: CA");
		break;
	case CERTYPE_BGPSEC:
		pr_val_debug("Type: BGPsec EE. Ignoring...");
//		error = handle_bgpsec(cert, x509stack_peek_resources(
//		    validation_certstack(state)), rpp_parent);
		goto end;
	default:
		pr_val_debug("Type: Unknown. Ignoring...");
		goto end;
	}

	error = certificate_validate_rfc6487(cert);
	if (error)
		goto end;

	error = (cert->type == CERTYPE_TA)
	    ? validate_ta_extensions(cert)
	    : validate_ca_extensions(cert);
	if (error)
		goto end;

	error = init_resources(cert);

end:	fnstack_pop();
	return error;
}

static int
certificate_traverse(struct rpki_certificate *ca, struct cert_stack *stack)
{
	struct cache_cage *cage;
	char const *mft;
	array_index i;
	struct cache_mapping *map;
	char const *ext;
	int error;

	error = certificate_validate(ca);
	if (error)
		return error;

	if (ca->type != CERTYPE_TA && ca->type != CERTYPE_CA)
		return 0;

	cage = cache_refresh_sias(&ca->sias);
	if (!cage)
		return pr_val_err("caRepository '%s' could not be refreshed, "
		    "and there is no fallback in the cache. "
		    "I'm going to have to skip it.", ca->sias.caRepository);

retry:	mft = cage_map_file(cage, ca->sias.rpkiManifest);
	if (!mft) {
		if (cage_disable_refresh(cage))
			goto retry;
		error = pr_val_err("caRepository '%s' is missing a manifest.",
		    ca->sias.caRepository);
		goto end;
	}

	error = manifest_validate(ca->sias.rpkiManifest, mft, cage, ca);
	if (error) {
		if (cage_disable_refresh(cage))
			goto retry;
		goto end;
	}

	for (i = 0; i < ca->rpp.nfiles; i++) {
		map = ca->rpp.files + i;
		ext = map->url + strlen(map->url) - 4;
		if (strcmp(ext, ".cer") == 0)
			certificate_stack_push(stack, map, ca);
		else if (strcmp(ext, ".roa") == 0)
			roa_traverse(map, ca);
		else if (strcmp(ext, ".gbr") == 0)
			ghostbusters_traverse(map, ca);
	}

end:	free(cage);
	return error;
}

int
traverse_tree(struct cache_mapping const *ta_map, struct validation *state)
{
	struct cert_stack stack;
	struct rpki_certificate ta = { .map = *ta_map };
	struct rpki_certificate *ca;
	int error;

	SLIST_INIT(&stack);

	/* == Root certificate == */
	error = certificate_traverse(&ta, &stack); // XXX clean up TA
	if (error)
		return error;

	/*
	 * From now on, the tree should be considered valid, even if subsequent
	 * certificates fail.
	 * (the root validated successfully; subtrees are isolated problems.)
	 */

	/* == Every other certificate == */
	while (!SLIST_EMPTY(&stack)) {
		ca = SLIST_FIRST(&stack);
		SLIST_REMOVE_HEAD(&stack, lh);

		certificate_traverse(ca, &stack);

		rpki_certificate_free(ca);
	}

	return 0;
}
