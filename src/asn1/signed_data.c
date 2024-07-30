#include "asn1/signed_data.h"

#include "algorithm.h"
#include "alloc.h"
#include "asn1/asn1c/ContentType.h"
#include "asn1/asn1c/ContentTypePKCS7.h"
#include "asn1/asn1c/MessageDigest.h"
#include "asn1/asn1c/SignedDataPKCS7.h"
#include "asn1/decode.h"
#include "asn1/oid.h"
#include "config.h"
#include "hash.h"
#include "log.h"
#include "object/certificate.h"
#include "thread_var.h"

static const OID oid_cta = OID_CONTENT_TYPE_ATTR;
static const OID oid_mda = OID_MESSAGE_DIGEST_ATTR;
static const OID oid_sta = OID_SIGNING_TIME_ATTR;
static const OID oid_bsta = OID_BINARY_SIGNING_TIME_ATTR;

void
eecert_init(struct ee_cert *ee, STACK_OF(X509_CRL) *crls, bool force_inherit)
{
	ee->res = resources_create(RPKI_POLICY_RFC6484, force_inherit);
	ee->crls = crls;
	memset(&ee->refs, 0, sizeof(ee->refs));
}

void
eecert_cleanup(struct ee_cert *ee)
{
	resources_destroy(ee->res);
	refs_cleanup(&ee->refs);
}

static int
get_sid(struct SignerInfo *sinfo, OCTET_STRING_t **result)
{
	switch (sinfo->sid.present) {
	case SignerIdentifier_PR_subjectKeyIdentifier:
		*result = &sinfo->sid.choice.subjectKeyIdentifier;
		return 0;
	case SignerIdentifier_PR_issuerAndSerialNumber:
		return pr_val_err("Signer Info's sid is an IssuerAndSerialNumber, not a SubjectKeyIdentifier.");
	case SignerIdentifier_PR_NOTHING:
		break;
	}

	return pr_val_err("Signer Info's sid is not a SubjectKeyIdentifier.");
}

static int
handle_sdata_certificate(ANY_t *cert_encoded, struct ee_cert *ee,
    OCTET_STRING_t *sid, ANY_t *signedData, SignatureValue_t *signature)
{
	const unsigned char *otmp, *tmp;
	X509 *cert;
	enum rpki_policy policy;
	int error;

	/*
	 * No need to validate certificate chain length, since we just arrived
	 * to a tree leaf. Loops aren't possible.
	 */

	pr_val_debug("EE Certificate (embedded) {");

	/*
	 * "If the call is successful *in is incremented to the byte following
	 * the parsed data."
	 * (https://www.openssl.org/docs/man1.0.2/crypto/d2i_X509_fp.html)
	 * We definitely don't want @any->buf to be modified, so use a dummy
	 * pointer.
	 */
	tmp = (const unsigned char *) cert_encoded->buf;
	otmp = tmp;
	cert = d2i_X509(NULL, &tmp, cert_encoded->size);
	if (cert == NULL) {
		error = val_crypto_err("Signed object's 'certificate' element does not decode into a Certificate");
		goto end1;
	}
	if (tmp != otmp + cert_encoded->size) {
		error = val_crypto_err("Signed object's 'certificate' element contains trailing garbage");
		goto end2;
	}

	x509_name_pr_debug("Issuer", X509_get_issuer_name(cert));

	error = certificate_validate_chain(cert, ee->crls);
	if (error)
		goto end2;
	error = certificate_validate_rfc6487(cert, CERTYPE_EE);
	if (error)
		goto end2;
	error = certificate_validate_extensions_ee(cert, sid, &ee->refs,
	    &policy);
	if (error)
		goto end2;
	error = certificate_validate_aia(ee->refs.caIssuers, cert);
	if (error)
		goto end2;
	error = certificate_validate_signature(cert, signedData, signature);
	if (error)
		goto end2;

	resources_set_policy(ee->res, policy);
	error = certificate_get_resources(cert, ee->res, CERTYPE_EE);
	if (error)
		goto end2;

end2:
	X509_free(cert);
end1:
	pr_val_debug("}");
	return error;
}

/* rfc6488#section-2.1.6.4.1 */
static int
validate_content_type_attribute(CMSAttributeValue_t *value,
    EncapsulatedContentInfo_t *eci)
{
	OBJECT_IDENTIFIER_t *attrValues;
	OBJECT_IDENTIFIER_t *eContentType;
	int error;

	error = asn1_decode_any(value, &asn_DEF_OBJECT_IDENTIFIER,
	    (void **) &attrValues, true);
	if (error)
		return error;
	eContentType = &eci->eContentType;

	if (!oid_equal(attrValues, eContentType))
		error = pr_val_err("The attrValues for the content-type attribute does not match the eContentType in the EncapsulatedContentInfo.");

	ASN_STRUCT_FREE(asn_DEF_OBJECT_IDENTIFIER, attrValues);
	return error;
}

static int
validate_message_digest_attribute(CMSAttributeValue_t *value,
    EncapsulatedContentInfo_t *eci)
{
	MessageDigest_t *digest;
	int error;

	if (eci->eContent == NULL)
		return pr_val_err("There's no content being signed.");

	error = asn1_decode_any(value, &asn_DEF_MessageDigest,
	    (void **) &digest, true);
	if (error)
		return error;

	error = hash_validate(hash_get_sha256(), eci->eContent->buf,
	    eci->eContent->size, digest->buf, digest->size);
	if (error > 0)
		pr_val_err("The content's hash does not match the Message-Digest Attribute.");

	ASN_STRUCT_FREE(asn_DEF_MessageDigest, digest);
	return error;
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

	if (sinfo->signedAttrs == NULL)
		return pr_val_err("The SignerInfo's signedAttrs field is NULL.");

	for (i = 0; i < sinfo->signedAttrs->list.count; i++) {
		attr = sinfo->signedAttrs->list.array[i];
		if (attr == NULL) {
			pr_val_err("SignedAttrs array element %u is NULL.", i);
			continue;
		}
		attrs = &attr->attrValues;

		if (attrs->list.count != 1) {
			return pr_val_err("signedAttrs's attribute set size (%d) is different than 1",
			    attr->attrValues.list.count);
		}
		if (attrs->list.array == NULL || attrs->list.array[0] == NULL)
			pr_crit("Array size is 1 but array is NULL.");

		error = oid2arcs(&attr->attrType, &attrType);
		if (error)
			return error;

		if (ARCS_EQUAL_OIDS(&attrType, oid_cta)) {
			if (content_type_found) {
				pr_val_err("Multiple ContentTypes found.");
				goto illegal_attrType;
			}
			error = validate_content_type_attribute(
			    attr->attrValues.list.array[0], eci);
			content_type_found = true;

		} else if (ARCS_EQUAL_OIDS(&attrType, oid_mda)) {
			if (message_digest_found) {
				pr_val_err("Multiple MessageDigests found.");
				goto illegal_attrType;
			}
			error = validate_message_digest_attribute(
			    attr->attrValues.list.array[0], eci);
			message_digest_found = true;

		} else if (ARCS_EQUAL_OIDS(&attrType, oid_sta)) {
			if (signing_time_found) {
				pr_val_err("Multiple SigningTimes found.");
				goto illegal_attrType;
			}
			error = 0; /* No validations needed for now. */
			signing_time_found = true;

		} else if (ARCS_EQUAL_OIDS(&attrType, oid_bsta)) {
			if (binary_signing_time_found) {
				pr_val_err("Multiple BinarySigningTimes found.");
				goto illegal_attrType;
			}
			error = 0; /* No validations needed for now. */
			binary_signing_time_found = true;

		} else {
			/* rfc6488#section-3.1.g */
			pr_val_err("Illegal attrType OID in SignerInfo.");
			goto illegal_attrType;
		}

		free_arcs(&attrType);

		if (error)
			return error;
	}

	/* rfc6488#section-3.1.f */
	if (!content_type_found)
		return pr_val_err("SignerInfo lacks a ContentType attribute.");
	if (!message_digest_found)
		return pr_val_err("SignerInfo lacks a MessageDigest attribute.");

	return 0;

illegal_attrType:
	free_arcs(&attrType);
	return -EINVAL;
}

int
signed_data_validate(ANY_t *encoded, struct SignedData *sdata,
		     struct ee_cert *ee)
{
	struct SignerInfo *sinfo;
	OCTET_STRING_t *sid = NULL;
	unsigned long version;
	int error;

	/* rfc6488#section-2.1 */
	if (sdata->signerInfos.list.count != 1) {
		return pr_val_err("The SignedData's SignerInfo set is supposed to have only one element. (%d given.)",
		    sdata->signerInfos.list.count);
	}

	/* rfc6488#section-2.1.1 */
	/* rfc6488#section-3.1.b */
	error = asn_INTEGER2ulong(&sdata->version, &version);
	if (error) {
		if (errno) {
			pr_val_err("Error converting SignedData version: %s",
			    strerror(errno));
		}
		return pr_val_err("The SignedData version isn't a valid unsigned long");
	}
	if (version != 3) {
		return pr_val_err("The SignedData version is only allowed to be 3. (Was %lu.)",
		    version);
	}

	/* rfc6488#section-2.1.2 */
	/* rfc6488#section-3.1.j 1/2 */
	if (sdata->digestAlgorithms.list.count != 1) {
		return pr_val_err("The SignedData's digestAlgorithms set is supposed to have only one element. (%d given.)",
		    sdata->digestAlgorithms.list.count);
	}

	/*
	 * No idea what to do with struct DigestAlgorithmIdentifier; it's not
	 * defined anywhere and the code always seems to fall back to
	 * AlgorithmIdentifier instead. There's no API.
	 * This seems to work fine.
	 */
	error = validate_cms_hashing_algorithm(
	    (AlgorithmIdentifier_t *) sdata->digestAlgorithms.list.array[0],
	    "SignedData");
	if (error)
		return error;

	/* rfc6488#section-2.1.3 */
	/* Specific sub-validations will be performed later by calling code. */

	/*
	 * We will validate the certificate later, because we need the sid
	 * first. We should also probably validate the signed attributes first
	 * as well.
	 */

	/* rfc6488#section-2.1.5 */
	/* rfc6488#section-3.1.d */
	if (sdata->crls != NULL && sdata->crls->list.count > 0)
		return pr_val_err("The SignedData contains at least one CRL.");

	/* rfc6488#section-2.1.6.1 */
	/* rfc6488#section-3.1.e */
	sinfo = sdata->signerInfos.list.array[0];
	if (sinfo == NULL)
		return pr_val_err("The SignerInfo object is NULL.");

	error = asn_INTEGER2ulong(&sinfo->version, &version);
	if (error) {
		if (errno) {
			pr_val_err("Error converting SignerInfo version: %s",
			    strerror(errno));
		}
		return pr_val_err("The SignerInfo version isn't a valid unsigned long");
	}
	if (version != 3) {
		return pr_val_err("The SignerInfo version is only allowed to be 3. (Was %lu.)",
		    version);
	}

	/* rfc6488#section-2.1.6.2 */
	/* rfc6488#section-3.1.c 2/2 */
	/* (Most of this requirement is in handle_ski_ee().) */
	error = get_sid(sinfo, &sid);
	if (error)
		return error;

	/* rfc6488#section-2.1.6.3 */
	/* rfc6488#section-3.1.j 2/2 */
	error = validate_cms_hashing_algorithm(&sinfo->digestAlgorithm,
	    "SignerInfo");
	if (error)
		return error;

	/* rfc6488#section-2.1.6.4 */
	error = validate_signed_attrs(sinfo, &sdata->encapContentInfo);
	if (error)
		return error;

	/* rfc6488#section-2.1.6.5 */
	/* rfc6488#section-3.1.k */
	error = validate_cms_signature_algorithm(&sinfo->signatureAlgorithm);
	if (error)
		return error;

	/* rfc6488#section-2.1.6.6 */
	/* Signature handled below. */

	/* rfc6488#section-2.1.6.7 */
	/* rfc6488#section-3.1.i */
	if (sinfo->unsignedAttrs != NULL && sinfo->unsignedAttrs->list.count > 0)
		return pr_val_err("SignerInfo has at least one unsignedAttr.");

	/* rfc6488#section-2.1.4 */
	/* rfc6488#section-3.1.c 1/2 */
	/* rfc6488#section-3.2 */
	/* rfc6488#section-3.3 */
	if (sdata->certificates == NULL)
		return pr_val_err("The SignedData does not contain certificates.");

	if (sdata->certificates->list.count != 1) {
		return pr_val_err("The SignedData contains %d certificates, one expected.",
		    sdata->certificates->list.count);
	}

	error = handle_sdata_certificate(sdata->certificates->list.array[0],
	    ee, sid, encoded, &sinfo->signature);
	if (error)
		return error;

	return 0;
}

/*
 * Function to handle 'Compatibility with PKCS #7' (RFC 5652 section 5.2.1:
 * "If the implementation is unable to ASN.1 decode the SignedData type using
 *  the CMS SignedData encapContentInfo eContent OCTET STRING syntax,
 *  then the implementation MAY attempt to decode the SignedData type
 *  using the PKCS #7 SignedData contentInfo content ANY syntax and
 *  compute the message digest accordingly."
 */
static int
signed_data_decode_pkcs7(ANY_t *coded, struct SignedData **result)
{
	struct SignedDataPKCS7 *sdata_pkcs7;
	struct SignedData *sdata;
	int error;

	error = asn1_decode_any(coded, &asn_DEF_SignedDataPKCS7,
	    (void **) &sdata_pkcs7, true);
	if (error)
		return error;

	sdata = pcalloc(1, sizeof(struct SignedData));

	/* Parse content as OCTET STRING */
	error = asn1_decode_any(sdata_pkcs7->encapContentInfo.eContent,
	    &asn_DEF_ContentTypePKCS7,
	    (void **) &sdata->encapContentInfo.eContent, true);
	if (error)
		goto release_sdata;

	/* Shallow copy to a SignedData struct */
	sdata->version = sdata_pkcs7->version;
	sdata->digestAlgorithms = sdata_pkcs7->digestAlgorithms;
	sdata->encapContentInfo.eContentType =
	    sdata_pkcs7->encapContentInfo.eContentType;
	sdata->certificates = sdata_pkcs7->certificates;
	sdata->crls = sdata_pkcs7->crls;
	sdata->signerInfos = sdata_pkcs7->signerInfos;

	/* Release what isnt's referenced */
	ASN_STRUCT_FREE(asn_DEF_ANY, sdata_pkcs7->encapContentInfo.eContent);
	free(sdata_pkcs7);

	*result = sdata;
	return 0;

release_sdata:
	free(sdata);
	ASN_STRUCT_FREE(asn_DEF_SignedDataPKCS7, sdata_pkcs7);
	return error;
}

int
signed_data_decode(ANY_t *encoded, struct SignedData **decoded)
{
	int error;

	error = asn1_decode_any(encoded, &asn_DEF_SignedData,
	    (void **) decoded, false);
	if (error) {
		/* Try to decode as PKCS content (RFC 5652 section 5.2.1) */
		error = signed_data_decode_pkcs7(encoded, decoded);
	}

	return error;
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
			    (void **) result, true);
		}
	}

	return -EINVAL;
}
