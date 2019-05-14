#include "algorithm.h"

#include <openssl/obj_mac.h>
#include "log.h"

/**
 * This function can also be used for CRLs.
 */
int
validate_certificate_signature_algorithm(int nid, char const *what)
{
	if (nid == NID_sha256WithRSAEncryption)
		return 0;

	return pr_err("%s's signature algorithm is NID '%d', not RSA+SHA256.",
	    what, nid);
}

int
validate_certificate_public_key_algorithm(int nid)
{
	/*
	 * TODO (whatever) RFC says sha256WithRSAEncryption, but everyone uses
	 * rsaEncryption.
	 */
	if (nid == NID_rsaEncryption || nid == NID_sha256WithRSAEncryption)
		return 0;

	return pr_err("Certificate's public key format is NID '%d', not RSA nor RSA+SHA256.",
	    nid);
}

int
validate_cms_hashing_algorithm(AlgorithmIdentifier_t *id, char const *what)
{
	int error;

	if (id == NULL)
		return pr_err("The hash algorithm of the '%s' is absent", what);

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
	 */
	if (id->parameters != NULL)
		pr_warn("The hash algorithm of the '%s' has parameters", what);

	return 0;
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
		return pr_err("The hash algorithm of the '%s' is absent", what);

	if (oid->size != sizeof(sha256))
		goto incorrect_oid;
	if (memcmp(sha256, oid->buf, sizeof(sha256)) != 0)
		goto incorrect_oid;

	return 0;

incorrect_oid:
	return pr_err("The hash algorithm of the '%s' is not SHA256.", what);
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
	int error;

	if (id == NULL)
		return pr_err("The signature algorithm is absent.");

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
	 */
	if (id->parameters != NULL) {
		error = incidence(INID_SIGNATURE_ALGORITHM_HAS_PARAMS,
		    "The signature algorithm has parameters.");
		if (error)
			return error;
	}

	return 0;

incorrect_oid:
	return pr_err("The Signature algorithm is not RSA nor RSA+SHA256.");
}
