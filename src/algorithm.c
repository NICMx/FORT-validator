#include "algorithm.h"

#include <stdbool.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>

#include "log.h"

static bool
is_asn1_null_object(ANY_t *any)
{
	return (any->size == 2) && (any->buf[0] == 5) && (any->buf[1] == 0);
}

static bool
is_asn1_null(ANY_t *any)
{
	return (any == NULL) || is_asn1_null_object(any);
}

/**
 * This function can also be used for CRLs.
 */
int
validate_certificate_signature_algorithm(int nid, char const *what)
{
	if (nid == NID_sha256WithRSAEncryption)
		return 0;

	return pr_val_err("%s's signature algorithm is NID '%d', not RSA+SHA256.",
	    what, nid);
}

/*
 * Expected algorithm for certs (expect BGPsec) according to RFC 7935
 */
int
validate_certificate_public_key_algorithm(X509_ALGOR *pa)
{
	int nid;

	/*
	 * RFC says sha256WithRSAEncryption, but current IETF concensus (and
	 * practice) say that the right one is rsaEncryption.
	 * https://mailarchive.ietf.org/arch/browse/sidr/
	 */
	nid = OBJ_obj2nid(pa->algorithm);
	if (nid == NID_rsaEncryption)
		return 0;

	return pr_val_err("Certificate's public key format is NID '%s', not rsaEncryption.",
	    OBJ_nid2sn(nid));
}

/*
 * Expected algorithm and parameters for BGPsec certs according to RFC 8608
 */
int
validate_certificate_public_key_algorithm_bgpsec(X509_ALGOR *pa)
{
	int nid;

	nid = OBJ_obj2nid(pa->algorithm);

	/* Validate algorithm and parameters (RFC 8608#section-3.1.1) */
	if (nid != NID_X9_62_id_ecPublicKey)
		return pr_val_err("Certificate's public key format is NID '%s', not id-ecPublicKey.",
		    OBJ_nid2sn(nid));

	if (pa->parameter == NULL)
		return pr_val_err("Certificate's public key algorithm MUST have parameters");

	if (pa->parameter->type != V_ASN1_OBJECT)
		return pr_val_err("Certificate's public key parameter type isn't valid");

	nid = OBJ_obj2nid((ASN1_OBJECT *)pa->parameter->value.object);
	if (nid != NID_X9_62_prime256v1)
		return pr_val_err("Certificate's public key format is NID '%s', not secp256r1 (a.k.a prime256v1).",
		    OBJ_nid2sn(nid));

	return 0;
}

int
validate_cms_hashing_algorithm(AlgorithmIdentifier_t *id, char const *what)
{
	int error;

	if (id == NULL)
		return pr_val_err("The hash algorithm of the '%s' is absent", what);

	error = validate_cms_hashing_algorithm_oid(&id->algorithm, what);
	if (error)
		return error;

	/*
	 * RFC 5754:
	 * There are two possible encodings for the AlgorithmIdentifier
	 * parameters field associated with these object identifiers.
	 * (...)
	 * some implementations encode parameters as a NULL element
	 * while others omit them entirely.  The correct encoding is to omit the
	 * parameters field;
	 *
	 * We will treat NULL object parameters as one type of error, and any
	 * other type of present parameters as a different error. The former
	 * will be silenceable, because many people are breaking the rule.
	 */
	if (id->parameters != NULL) {
		error = is_asn1_null_object(id->parameters)
		    ? incidence(INID_HASHALG_HAS_PARAMS,
		        "The hash algorithm of the '%s' has a NULL object as parameters",
		        what)
		    : pr_val_err("The hash algorithm of the '%s' has parameters",
		        what);
	}

	return error;
}

int
validate_cms_hashing_algorithm_oid(OBJECT_IDENTIFIER_t *oid, char const *what)
{
	/*
	 * RFC 7935:
	 * In CMS SignedData (...) The object identifier and
	 * parameters for SHA-256 (...) MUST be used for the
	 * SignedData digestAlgorithms field and the SignerInfo digestAlgorithm
	 * field.
	 */

	static const unsigned char sha256[] = {
	    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	};

	if (oid == NULL)
		return pr_val_err("The hash algorithm of the '%s' is absent", what);

	if (oid->size != sizeof(sha256))
		goto incorrect_oid;
	if (memcmp(sha256, oid->buf, sizeof(sha256)) != 0)
		goto incorrect_oid;

	return 0;

incorrect_oid:
	return pr_val_err("The hash algorithm of the '%s' is not SHA256.", what);
}

int
validate_cms_signature_algorithm(AlgorithmIdentifier_t *id)
{
	/*
	 * RFC 7935:
	 * In CMS SignedData, (...) RPKI implementations MUST
	 * accept either rsaEncryption or sha256WithRSAEncryption for the
	 * SignerInfo signatureAlgorithm field when verifying CMS SignedData
	 * objects (...).
	 */

	static const unsigned char pkcs1[] = {
	    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	};
	uint8_t last;

	if (id == NULL)
		return pr_val_err("The signature algorithm is absent.");

	/*
	 * rsaEncryption is { pkcs-1 1 }, and sha256WithRSAEncryption is
	 * { pkcs-1 11 }.
	 */
	if (id->algorithm.size != sizeof(pkcs1) + 1)
		goto incorrect_oid;
	if (memcmp(pkcs1, id->algorithm.buf, sizeof(pkcs1)) != 0)
		goto incorrect_oid;
	last = id->algorithm.buf[sizeof(pkcs1)];
	if (last != 1 && last != 11)
		goto incorrect_oid;

	/*
	 * This one's a royal mess.
	 *
	 * RFC 7935:
	 * The object identifier and parameters for rsaEncryption
	 * [RFC3370] MUST be used for the SignerInfo signatureAlgorithm field
	 * when generating CMS SignedData objects.
	 *
	 * RFC 3370 (1):
	 * When the rsaEncryption algorithm identifier is used, the
	 * AlgorithmIdentifier parameters field MUST contain NULL.
	 *
	 * RFC 4055 (11):
	 * When any of these four object identifiers appears within an
	 * AlgorithmIdentifier, the parameters MUST be NULL.  Implementations
	 * MUST accept the parameters being absent as well as present.
	 *
	 * I don't know if "MUST contain NULL" means that it must be absent,
	 * or whether it must contain a NULL ASN object. Everyone is doing the
	 * latter, which you think would be the logical option, but then 3370
	 * throws this curveball at us:
	 *
	 * There are two possible encodings for the SHA-1 AlgorithmIdentifier
	 * parameters field.  The two alternatives arise from the fact that when
	 * the 1988 syntax for AlgorithmIdentifier was translated into the 1997
	 * syntax, the OPTIONAL associated with the AlgorithmIdentifier
	 * parameters got lost.  Later the OPTIONAL was recovered via a defect
	 * report, but by then many people thought that algorithm parameters
	 * were mandatory.  Because of this history some implementations encode
	 * parameters as a NULL element and others omit them entirely.  The
	 * correct encoding is to omit the parameters field; however,
	 * implementations MUST also handle a SHA-1 AlgorithmIdentifier
	 * parameters field which contains a NULL.
	 *
	 * It does seem to be talking about SHA-1 only, but it's just not clear,
	 * because it doesn't care to ellaborate in the rsaEncryption section at
	 * all. Even though it's aware of the ambiguity, it just says "MUST
	 * contain NULL." It doesn't say "MUST be empty" or "MUST contain a NULL
	 * object."
	 *
	 * I really don't think this is worth making a fuss over, so we'll just
	 * accept both.
	 */
	if (id->parameters != NULL && !is_asn1_null(id->parameters))
		return pr_val_err("The signature algorithm has parameters.");

	return 0;

incorrect_oid:
	return pr_val_err("The Signature algorithm is not RSA nor RSA+SHA256.");
}
