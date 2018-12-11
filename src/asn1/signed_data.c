#include "signed_data.h"

#include <errno.h>
#include <libcmscodec/ContentType.h>
#include "log.h"
#include "oid.h"
#include "asn1/decode.h"
#include "object/certificate.h"

/* TODO more consistent and informative error/warning messages.*/

static const OID oid_sha224 = OID_SHA224;
static const OID oid_sha256 = OID_SHA256;
static const OID oid_sha384 = OID_SHA384;
static const OID oid_sha512 = OID_SHA512;
static const OID oid_cta = OID_CONTENT_TYPE_ATTR;
static const OID oid_mda = OID_MESSAGE_DIGEST_ATTR;
static const OID oid_sta = OID_SIGNING_TIME_ATTR;
static const OID oid_bsta = OID_BINARY_SIGNING_TIME_ATTR;

/*
 * The correctness of this function depends on @MAX_ARCS being faithful to all
 * the known OIDs declared *in the project*.
 */
static int
is_digest_algorithm(AlgorithmIdentifier_t *aid, bool *result)
{
	struct oid_arcs arcs;
	int error;

	error = oid2arcs(&aid->algorithm, &arcs);
	if (error)
		return error;

	*result = ARCS_EQUAL_OIDS(&arcs, oid_sha224)
	       || ARCS_EQUAL_OIDS(&arcs, oid_sha256)
	       || ARCS_EQUAL_OIDS(&arcs, oid_sha384)
	       || ARCS_EQUAL_OIDS(&arcs, oid_sha512);

	free_arcs(&arcs);
	return 0;
}

static int
handle_sdata_certificate(ANY_t *any, struct resources *res)
{
	const unsigned char *tmp;
	X509 *cert;
	int error;

	pr_debug_add("Certificate (embedded) {");

	/*
	 * "If the call is successful *in is incremented to the byte following
	 * the parsed data."
	 * (https://www.openssl.org/docs/man1.0.2/crypto/d2i_X509_fp.html)
	 * We definitely don't want @any->buf to be modified, so use a dummy
	 * pointer.
	 */
	tmp = (const unsigned char *) any->buf;

	cert = d2i_X509(NULL, &tmp, any->size);
	if (cert == NULL) {
		error = crypto_err("Signed object's 'certificate' element does not decode into a Certificate");
		goto end1;
	}

	error = certificate_validate(cert, NULL); /* TODO crls */
	if (error)
		goto end2;

	if (res != NULL) {
		error = certificate_get_resources(cert, res);
		if (error)
			goto end2;
	}

	/* TODO maybe spill a warning if the certificate has children? */

end2:
	X509_free(cert);
end1:
	pr_debug_rm("}");
	return error;
}

static int
validate_content_type_attribute(CMSAttributeValue_t *value,
    EncapsulatedContentInfo_t *eci)
{
	struct oid_arcs attrValue_arcs;
	struct oid_arcs EncapContentInfo_arcs;
	int error;

	/* rfc6488#section-3.1.h */
	/* TODO (performance) Can't we just do a memcmp? */

	error = any2arcs(value, &attrValue_arcs);
	if (error)
		return error;

	error = oid2arcs(&eci->eContentType, &EncapContentInfo_arcs);
	if (error) {
		free_arcs(&attrValue_arcs);
		return error;
	}

	if (!arcs_equal(&attrValue_arcs, &EncapContentInfo_arcs)) {
		pr_err("The eContentType in the EncapsulatedContentInfo does not match the attrValues in the content-type attribute.");
		error = -EINVAL;
	}

	free_arcs(&EncapContentInfo_arcs);
	free_arcs(&attrValue_arcs);
	return error;
}

static int
validate_message_digest_attribute(CMSAttributeValue_t *value)
{
	return 0; /* TODO need the content being signed */
}

static int
validate_signed_attrs(struct SignerInfo *sinfo, EncapsulatedContentInfo_t *eci)
{
	struct CMSAttribute *attr;
	struct CMSAttribute__attrValues *attrs;
	struct oid_arcs attrType;
	unsigned int i;
	bool content_type_found = false;
	bool message_digest_found = false;
	bool signing_time_found = false;
	bool binary_signing_time_found = false;
	int error;

	if (sinfo->signedAttrs == NULL) {
		pr_err("The SignerInfo's signedAttrs field is NULL.");
		return -EINVAL;
	}

	for (i = 0; i < sinfo->signedAttrs->list.count; i++) {
		attr = sinfo->signedAttrs->list.array[i];
		if (attr == NULL) {
			pr_err("SignedAttrs array element %u is NULL.", i);
			continue;
		}
		attrs = &attr->attrValues;

		if (attrs->list.count != 1) {
			pr_err(0,
			    "signedAttrs's attribute set size (%d) is different than 1.",
			    attr->attrValues.list.count);
			return -EINVAL;
		}
		if (attrs->list.array == NULL || attrs->list.array[0] == NULL) {
			pr_err("Programming error: Array size is 1 but array itself is NULL.");
			return -EINVAL;
		}

		error = oid2arcs(&attr->attrType, &attrType);
		if (error)
			return error;

		if (ARCS_EQUAL_OIDS(&attrType, oid_cta)) {
			if (content_type_found) {
				pr_err("Multiple ContentTypes found.");
				goto illegal_attrType;
			}
			error = validate_content_type_attribute(
			    attr->attrValues.list.array[0], eci);
			content_type_found = true;

		} else if (ARCS_EQUAL_OIDS(&attrType, oid_mda)) {
			if (message_digest_found) {
				pr_err("Multiple MessageDigests found.");
				goto illegal_attrType;
			}
			error = validate_message_digest_attribute(
			    attr->attrValues.list.array[0]);
			message_digest_found = true;

		} else if (ARCS_EQUAL_OIDS(&attrType, oid_sta)) {
			if (signing_time_found) {
				pr_err("Multiple SigningTimes found.");
				goto illegal_attrType;
			}
			error = 0; /* No validations needed for now. */
			signing_time_found = true;

		} else if (ARCS_EQUAL_OIDS(&attrType, oid_bsta)) {
			if (binary_signing_time_found) {
				pr_err("Multiple BinarySigningTimes found.");
				goto illegal_attrType;
			}
			error = 0; /* No validations needed for now. */
			binary_signing_time_found = true;

		} else {
			/* rfc6488#section-3.1.g */
			pr_err("Illegal attrType OID in SignerInfo.");
			goto illegal_attrType;
		}

		free_arcs(&attrType);

		if (error)
			return error;
	}

	/* rfc6488#section-3.1.f */
	if (!content_type_found) {
		pr_err("SignerInfo lacks a ContentType attribute.");
		return -EINVAL;
	}
	if (!message_digest_found) {
		pr_err("SignerInfo lacks a MessageDigest attribute.");
		return -EINVAL;
	}

	return 0;

illegal_attrType:
	free_arcs(&attrType);
	return -EINVAL;
}

static int
validate(struct SignedData *sdata, struct resources *res)
{
	struct SignerInfo *sinfo;
	bool is_digest;
	int error;

	/* rfc6488#section-2.1 */
	if (sdata->signerInfos.list.count != 1) {
		pr_err("The SignedData's SignerInfo set is supposed to have only one element. (%d given.)",
		    sdata->signerInfos.list.count);
		return -EINVAL;
	}

	/* rfc6488#section-2.1.1 */
	/* rfc6488#section-3.1.b */
	if (sdata->version != 3) {
		pr_err("The SignedData version is only allowed to be 3. (Was %ld.)",
		    sdata->version);
		return -EINVAL;
	}

	/* rfc6488#section-2.1.2 */
	/* rfc6488#section-3.1.j 1/2 */
	if (sdata->digestAlgorithms.list.count != 1) {
		pr_err("The SignedData's digestAlgorithms set is supposed to have only one element. (%d given.)",
		    sdata->digestAlgorithms.list.count);
		return -EINVAL;
	}

	/*
	 * No idea what to do with struct DigestAlgorithmIdentifier; it's not
	 * defined anywhere and the code always seems to fall back to
	 * AlgorithmIdentifier instead. There's no API.
	 * This seems to work fine.
	 */
	error = is_digest_algorithm(
	    (AlgorithmIdentifier_t *) sdata->digestAlgorithms.list.array[0],
	    &is_digest);
	if (error)
		return error;
	if (!is_digest) {
		pr_err("The SignedData's digestAlgorithm OID is not listed in RFC 5754.");
		return -EINVAL;
	}

	/* section-2.1.3 */
	/* Specific sub-validations will be performed later by calling code. */

	/* rfc6488#section-2.1.4 */
	/* rfc6488#section-3.1.c 1/2 */
	if (sdata->certificates == NULL) {
		pr_err("The SignedData does not contain certificates.");
		return -EINVAL;
	}

	if (sdata->certificates->list.count != 1) {
		pr_err("The SignedData contains %d certificates, one expected.",
		    sdata->certificates->list.count);
		return -EINVAL;
	}

	error = handle_sdata_certificate(sdata->certificates->list.array[0],
	    res);
	if (error)
		return error;

	/* rfc6488#section-2.1.5 */
	/* rfc6488#section-3.1.d */
	if (sdata->crls != NULL && sdata->crls->list.count > 0) {
		pr_err("The SignedData contains at least one crls.");
		return -EINVAL;
	}

	/* rfc6488#section-2.1.6.1 */
	/* rfc6488#section-3.1.e */
	sinfo = sdata->signerInfos.list.array[0];
	if (sinfo == NULL) {
		pr_err("The SignerInfo object is NULL.");
		return -EINVAL;
	}
	if (sinfo->version != 3) {
		pr_err("The SignerInfo version is only allowed to be 3. (Was %ld.)",
		    sinfo->version);
		return -EINVAL;
	}

	/* rfc6488#section-2.1.6.2 */
	/* rfc6488#section-3.1.c 2/2 */
	/*
	 * TODO need the "EE certificate carried in the CMS certificates field."
	 */

	/* rfc6488#section-2.1.6.3 */
	/* rfc6488#section-3.1.j 2/2 */
	error = is_digest_algorithm(
	    (AlgorithmIdentifier_t *) &sinfo->digestAlgorithm, &is_digest);
	if (error)
		return error;
	if (!is_digest) {
		pr_err("The SignerInfo digestAlgorithm OID is not listed in RFC 5754.");
		return -EINVAL;
	}

	/* rfc6488#section-2.1.6.4 */
	error = validate_signed_attrs(sinfo, &sdata->encapContentInfo);
	if (error)
		return error;

	/* rfc6488#section-2.1.6.5 */
	/* rfc6488#section-3.1.k */
	/*
	 * RFC 6485 was obsoleted by 7935. 7935 simply refers to 5652.
	 *
	 * RFC 5652:
	 *
	 * > Since each signer can employ a different digital signature
	 * > technique, and future specifications could update the syntax, all
	 * > implementations MUST gracefully handle unimplemented versions of
	 * > SignerInfo.  Further, since all implementations will not support
	 * > every possible signature algorithm, all implementations MUST
	 * > gracefully handle unimplemented signature algorithms when they are
	 * > encountered.
	 *
	 * So, nothing to do for now.
	 */

	/* rfc6488#section-2.1.6.6 */
	/* Again, nothing to do for now. */

	/* rfc6488#section-2.1.6.7 */
	/* rfc6488#section-3.1.i */
	if (sinfo->unsignedAttrs != NULL && sinfo->unsignedAttrs->list.count > 0) {
		pr_err("SignerInfo has at least one unsignedAttr.");
		return -EINVAL;
	}

	/* rfc6488#section-3.2 */
	/* rfc6488#section-3.3 */
	/* TODO */

	return 0;
}

int
signed_data_decode(ANY_t *coded, struct SignedData **result,
    struct resources *res)
{
	struct SignedData *sdata;
	int error;

	/* rfc6488#section-3.1.l TODO this is BER, not guaranteed to be DER. */
	error = asn1_decode_any(coded, &asn_DEF_SignedData, (void **) &sdata);
	if (error)
		return error;

	error = validate(sdata, res);
	if (error) {
		signed_data_free(sdata);
		return error;
	}

	*result = sdata;
	return 0;
}

void
signed_data_free(struct SignedData *sdata)
{
	ASN_STRUCT_FREE(asn_DEF_SignedData, sdata);
}

/* Caller must free *@result. */
int
get_content_type_attr(struct SignedData *sdata, OBJECT_IDENTIFIER_t **result)
{
	struct SignedAttributes *signedAttrs;
	struct CMSAttribute *attr;
	int i;
	int error;
	struct oid_arcs arcs;
	bool equal;

	if (sdata == NULL)
		return -EINVAL;
	if (sdata->signerInfos.list.array == NULL)
		return -EINVAL;
	if (sdata->signerInfos.list.array[0] == NULL)
		return -EINVAL;

	signedAttrs = sdata->signerInfos.list.array[0]->signedAttrs;
	if (signedAttrs->list.array == NULL)
		return -EINVAL;

	for (i = 0; i < signedAttrs->list.count; i++) {
		attr = signedAttrs->list.array[i];
		if (!attr)
			return -EINVAL;
		error = oid2arcs(&attr->attrType, &arcs);
		if (error)
			return -EINVAL;
		equal = ARCS_EQUAL_OIDS(&arcs, oid_cta);
		free_arcs(&arcs);
		if (equal) {
			if (attr->attrValues.list.array == NULL)
				return -EINVAL;
			if (attr->attrValues.list.array[0] == NULL)
				return -EINVAL;
			return asn1_decode_any(attr->attrValues.list.array[0],
			    &asn_DEF_OBJECT_IDENTIFIER,
			    (void **) result);
		}
	}

	return -EINVAL;
}
