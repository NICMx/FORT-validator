#include "signed_data.h"

#include <errno.h>
#include <libcmscodec/ContentType.h>
#include <libcmscodec/MessageDigest.h>

#include "config.h"
#include "log.h"
#include "oid.h"
#include "thread_var.h"
#include "asn1/decode.h"
#include "crypto/hash.h"
#include "object/certificate.h"

static const OID oid_cta = OID_CONTENT_TYPE_ATTR;
static const OID oid_mda = OID_MESSAGE_DIGEST_ATTR;
static const OID oid_sta = OID_SIGNING_TIME_ATTR;
static const OID oid_bsta = OID_BINARY_SIGNING_TIME_ATTR;

int
signed_object_args_init(struct signed_object_args *args,
    struct rpki_uri const *uri, STACK_OF(X509_CRL) *crls)
{
	args->res = resources_create();
	if (args->res == NULL)
		return pr_enomem();

	args->uri = uri;
	args->crls = crls;
	memset(&args->refs, 0, sizeof(args->refs));
	return 0;
}

void
signed_object_args_cleanup(struct signed_object_args *args)
{
	resources_destroy(args->res);
	refs_cleanup(&args->refs);
}

static int
is_digest_algorithm(AlgorithmIdentifier_t *id, char const *what)
{
	bool is_hash;
	int error;

	if (id == NULL)
		return pr_err("The %s algorithm is NULL.", what);

	error = hash_is_sha256(&id->algorithm, &is_hash);
	if (error)
		return error;
	if (!is_hash)
		return pr_err("The %s algorithm is not SHA256.", what);

	return 0;
}

static int
get_sid(struct SignerInfo *sinfo, OCTET_STRING_t **result)
{
	switch (sinfo->sid.present) {
	case SignerIdentifier_PR_subjectKeyIdentifier:
		*result = &sinfo->sid.choice.subjectKeyIdentifier;
		return 0;
	case SignerIdentifier_PR_issuerAndSerialNumber:
		return pr_err("Signer Info's sid is an IssuerAndSerialNumber, not a SubjectKeyIdentifier.");
	case SignerIdentifier_PR_NOTHING:
		break;
	}

	return pr_err("Signer Info's sid is not a SubjectKeyIdentifier.");
}

static int
handle_sdata_certificate(ANY_t *any, struct signed_object_args *args,
    OCTET_STRING_t *sid)
{
	struct validation *state;
	const unsigned char *tmp;
	X509 *cert;
	enum rpki_policy policy;
	int error;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;
	if (sk_X509_num(validation_certs(state)) >= config_get_max_cert_depth())
		return pr_err("Certificate chain maximum depth exceeded.");

	pr_debug_add("EE Certificate (embedded) {");

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

	error = certificate_validate_chain(cert, args->crls);
	if (error)
		goto end2;
	error = certificate_validate_rfc6487(cert, false);
	if (error)
		goto end2;
	error = certificate_validate_extensions_ee(cert, sid, &args->refs,
	    &policy);
	if (error)
		goto end2;

	resources_set_policy(args->res, policy);
	error = certificate_get_resources(cert, args->res);
	if (error)
		goto end2;

end2:
	X509_free(cert);
end1:
	pr_debug_rm("}");
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
	    (void **) &attrValues);
	if (error)
		return error;
	eContentType = &eci->eContentType;

	if (!oid_equal(attrValues, eContentType))
		error = pr_err("The attrValues for the content-type attribute does not match the eContentType in the EncapsulatedContentInfo.");

	ASN_STRUCT_FREE(asn_DEF_OBJECT_IDENTIFIER, attrValues);
	return error;
}

static int
validate_message_digest_attribute(CMSAttributeValue_t *value,
    EncapsulatedContentInfo_t *eci)
{
	MessageDigest_t *digest;
	int error;

	if (eci->eContent == NULL) {
		pr_err("There's no content being signed.");
		return -EINVAL;
	}

	error = asn1_decode_any(value, &asn_DEF_MessageDigest,
	    (void **) &digest);
	if (error)
		return error;

	error = hash_validate_octet_string("sha256", digest, eci->eContent);
	if (error)
		pr_err("The content's hash does not match the Message-Digest Attribute.");

	free(digest);
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
		return pr_err("The SignerInfo's signedAttrs field is NULL.");

	for (i = 0; i < sinfo->signedAttrs->list.count; i++) {
		attr = sinfo->signedAttrs->list.array[i];
		if (attr == NULL) {
			pr_err("SignedAttrs array element %u is NULL.", i);
			continue;
		}
		attrs = &attr->attrValues;

		if (attrs->list.count != 1) {
			return pr_err("signedAttrs's attribute set size (%d) is different than 1",
			    attr->attrValues.list.count);
		}
		if (attrs->list.array == NULL || attrs->list.array[0] == NULL)
			return pr_crit("Array size is 1 but array is NULL.");

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
			    attr->attrValues.list.array[0], eci);
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
	if (!content_type_found)
		return pr_err("SignerInfo lacks a ContentType attribute.");
	if (!message_digest_found)
		return pr_err("SignerInfo lacks a MessageDigest attribute.");

	return 0;

illegal_attrType:
	free_arcs(&attrType);
	return -EINVAL;
}

static int
validate(struct SignedData *sdata, struct signed_object_args *args)
{
	struct SignerInfo *sinfo;
	OCTET_STRING_t *sid = NULL;
	unsigned long version;
	int error;

	/* rfc6488#section-2.1 */
	if (sdata->signerInfos.list.count != 1) {
		return pr_err("The SignedData's SignerInfo set is supposed to have only one element. (%d given.)",
		    sdata->signerInfos.list.count);
	}

	/* rfc6488#section-2.1.1 */
	/* rfc6488#section-3.1.b */
	error = asn_INTEGER2ulong(&sdata->version, &version);
	if (error) {
		if (errno)
			pr_errno(errno, "Error converting SignedData version");
		return pr_err("The SignedData version isn't a valid unsigned long");
	}
	if (version != 3) {
		return pr_err("The SignedData version is only allowed to be 3. (Was %lu.)",
		    version);
	}

	/* rfc6488#section-2.1.2 */
	/* rfc6488#section-3.1.j 1/2 */
	if (sdata->digestAlgorithms.list.count != 1) {
		return pr_err("The SignedData's digestAlgorithms set is supposed to have only one element. (%d given.)",
		    sdata->digestAlgorithms.list.count);
	}

	/*
	 * No idea what to do with struct DigestAlgorithmIdentifier; it's not
	 * defined anywhere and the code always seems to fall back to
	 * AlgorithmIdentifier instead. There's no API.
	 * This seems to work fine.
	 */
	error = is_digest_algorithm(
	    (AlgorithmIdentifier_t *) sdata->digestAlgorithms.list.array[0],
	    "SignedData");
	if (error)
		return error;

	/* rfc6488#section-2.1.3 */
	/* Specific sub-validations will be performed later by calling code. */

	/*
	 * We will validate the certificate later, because we need the sid
	 * first.
	 */

	/* rfc6488#section-2.1.5 */
	/* rfc6488#section-3.1.d */
	if (sdata->crls != NULL && sdata->crls->list.count > 0)
		return pr_err("The SignedData contains at least one CRL.");

	/* rfc6488#section-2.1.6.1 */
	/* rfc6488#section-3.1.e */
	sinfo = sdata->signerInfos.list.array[0];
	if (sinfo == NULL)
		return pr_err("The SignerInfo object is NULL.");

	error = asn_INTEGER2ulong(&sinfo->version, &version);
	if (error) {
		if (errno)
			pr_errno(errno, "Error converting SignerInfo version");
		return pr_err("The SignerInfo version isn't a valid unsigned long");
	}
	if (version != 3) {
		return pr_err("The SignerInfo version is only allowed to be 3. (Was %lu.)",
		    version);
	}

	/* rfc6488#section-2.1.6.2 */
	/* rfc6488#section-3.1.c 2/2 */
	/* (Most of this requirement is in handle_ski_ee().) */
	error = get_sid(sinfo, &sid);
	if (error)
		return error;

	/* rfc6488#section-2.1.4 */
	/* rfc6488#section-3.1.c 1/2 */
	if (sdata->certificates == NULL)
		return pr_err("The SignedData does not contain certificates.");

	if (sdata->certificates->list.count != 1) {
		return pr_err("The SignedData contains %d certificates, one expected.",
		    sdata->certificates->list.count);
	}

	error = handle_sdata_certificate(sdata->certificates->list.array[0],
	    args, sid);
	if (error)
		return error;

	/* rfc6488#section-2.1.6.3 */
	/* rfc6488#section-3.1.j 2/2 */
	error = is_digest_algorithm(&sinfo->digestAlgorithm, "SignerInfo");
	if (error)
		return error;

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
	 *
	 * TODO "In the certificate, the OID appears in the signature and
	 * signatureAlgorithm fields [RFC4055]." So it has to be the same as
	 * some other field?
	 */

	/* rfc6488#section-2.1.6.6 */
	/* Again, nothing to do for now. */

	/* rfc6488#section-2.1.6.7 */
	/* rfc6488#section-3.1.i */
	if (sinfo->unsignedAttrs != NULL && sinfo->unsignedAttrs->list.count > 0)
		return pr_err("SignerInfo has at least one unsignedAttr.");

	/* rfc6488#section-3.2 */
	/* rfc6488#section-3.3 */
	/* TODO (field) */

	return 0;
}

int
signed_data_decode(ANY_t *coded, struct signed_object_args *args,
    struct SignedData **result)
{
	struct SignedData *sdata;
	int error;

	/* rfc6488#section-3.1.l */
	/* TODO (next iteration) this is BER, not guaranteed to be DER. */
	error = asn1_decode_any(coded, &asn_DEF_SignedData, (void **) &sdata);
	if (error)
		return error;

	error = validate(sdata, args);
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
