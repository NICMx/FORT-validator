#include "signed_data.h"

#include <err.h>
#include <errno.h>
#include <libcmscodec/ContentType.h>
#include "oid.h"

/* TODO more consistent and informative error/warning messages.*/

static int
validate_content_type_attribute(CMSAttributeValue_t *value,
    EncapsulatedContentInfo_t *eci)
{
	/* TODO need to decode value. */

	/* eci->eContentType*/

	return 0;
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
	unsigned int i;
	bool content_type_found = false;
	bool message_digest_found = false;
	bool signing_time_found = false;
	bool binary_signing_time_found = false;
	int error;

	if (sinfo->signedAttrs == NULL) {
		warnx("The SignerInfo's signedAttrs field is NULL.");
		return -EINVAL;
	}

	for (i = 0; i < sinfo->signedAttrs->list.count; i++) {
		attr = sinfo->signedAttrs->list.array[i];
		if (attr == NULL) {
			warnx("SignedAttrs array element %u is NULL.", i);
			continue;
		}
		attrs = &attr->attrValues;

		if (attrs->list.count != 1) {
			warnx("signedAttrs's attribute set size (%d) is different than 1.",
			    attr->attrValues.list.count);
			return -EINVAL;
		}
		if (attrs->list.array == NULL || attrs->list.array[0] == NULL) {
			warnx("Programming error: Array size is 1 but array itself is NULL.");
			return -EINVAL;
		}

		if (OID_EQUALS(&attr->attrType, CONTENT_TYPE_ATTR_OID)) {
			if (content_type_found) {
				warnx("Multiple ContentTypes found.");
				return -EINVAL;
			}
			error = validate_content_type_attribute(attr->attrValues.list.array[0], eci);
			content_type_found = true;

		} else if (OID_EQUALS(&attr->attrType, MESSAGE_DIGEST_ATTR_OID)) {
			if (message_digest_found) {
				warnx("Multiple MessageDigests found.");
				return -EINVAL;
			}
			error = validate_message_digest_attribute(attr->attrValues.list.array[0]);
			message_digest_found = true;

		} else if (OID_EQUALS(&attr->attrType, SIGNING_TIME_ATTR_OID)) {
			if (signing_time_found) {
				warnx("Multiple SigningTimes found.");
				return -EINVAL;
			}
			error = 0; /* No validations needed for now. */
			signing_time_found = true;

		} else if (OID_EQUALS(&attr->attrType, BINARY_SIGNING_TIME_ATTR_OID)) {
			if (binary_signing_time_found) {
				warnx("Multiple BinarySigningTimes found.");
				return -EINVAL;
			}
			error = 0; /* No validations needed for now. */
			binary_signing_time_found = true;

		} else {
			warnx("Illegal attrType OID in SignerInfo.");
			return -EINVAL;
		}

		if (error)
			return error;
	}

	if (!content_type_found) {
		warnx("SignerInfo lacks a ContentType attribute.");
		return -EINVAL;
	}
	if (!message_digest_found) {
		warnx("SignerInfo lacks a MessageDigest attribute.");
		return -EINVAL;
	}

	return 0;
}

static int
validate(struct SignedData *sdata)
{
	char error_msg[256];
	size_t error_msg_size;
	int error;
	struct SignerInfo *sinfo;

	/* The lib's inbuilt validations. (Probably not much.) */
	error_msg_size = sizeof(error_msg);
	error = asn_check_constraints(&asn_DEF_SignedData, sdata, error_msg,
	    &error_msg_size);
	if (error == -1) {
		warnx("Error validating SignedData object: %s", error_msg);
		return -EINVAL;
	}

	/* rfc6488#section-2.1 */
	if (sdata->signerInfos.list.count != 1) {
		warnx("The SignedData's SignerInfo set is supposed to have only one element. (%d given.)",
		    sdata->signerInfos.list.count);
		return -EINVAL;
	}

	/* rfc6488#section-2.1.1 */
	if (sdata->version != 3) {
		warnx("The SignedData version is only allowed to be 3. (Was %ld.)",
		    sdata->version);
		return -EINVAL;
	}

	/* rfc6488#section-2.1.2 */
	if (sdata->digestAlgorithms.list.count != 1) {
		warnx("The SignedData's digestAlgorithms set is supposed to have only one element. (%d given.)",
		    sdata->digestAlgorithms.list.count);
		return -EINVAL;
	}

	/*
	 * No idea what to do with struct DigestAlgorithmIdentifier; it's not
	 * defined anywhere and the code always seems to fall back to
	 * AlgorithmIdentifier instead. There's no API.
	 * This seems to work fine.
	 */
	if (!is_digest_algorithm((DigestAlgorithmIdentifier_t *) sdata->digestAlgorithms.list.array[0])) {
		warnx("The SignedData's digestAlgorithm OID is not listed in RFC 5754.");
		return -EINVAL;
	}

	/* section-2.1.3 */
	/* TODO need a callback for specific signed object types */

	/* rfc6488#section-2.1.4 */
	if (sdata->certificates == NULL) {
		warnx("The SignedData does not contain certificates.");
		return -EINVAL;
	}

	if (sdata->certificates->list.count != 1) {
		warnx("The SignedData contains %d certificates, one expected.",
		    sdata->certificates->list.count);
		return -EINVAL;
	}

	/* rfc6488#section-2.1.5 */
	if (sdata->crls != NULL && sdata->crls->list.count > 0) {
		warnx("The SignedData contains at least one crls.");
		return -EINVAL;
	}

	/* rfc6488#section-2.1.6.1 */
	sinfo = sdata->signerInfos.list.array[0];
	if (sinfo == NULL) {
		warnx("The SignerInfo object is NULL.");
		return -EINVAL;
	}
	if (sinfo->version != 3) {
		warnx("The SignerInfo version is only allowed to be 3. (Was %ld.)",
		    sinfo->version);
		return -EINVAL;
	}

	/* rfc6488#section-2.1.6.2 */
	/*
	 * TODO need the "EE certificate carried in the CMS certificates field."
	 */

	/* rfc6488#section-2.1.6.3 */
	if (!is_digest_algorithm((AlgorithmIdentifier_t *) &sinfo->digestAlgorithm)) {
		warnx("The SignerInfo digestAlgorithm OID is not listed in RFC 5754.");
		return -EINVAL;
	}

	/* rfc6488#section-2.1.6.4 */
	error = validate_signed_attrs(sinfo, &sdata->encapContentInfo);
	if (error)
		return error;

	/* rfc6488#section-2.1.6.5 */
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
	if (sinfo->unsignedAttrs != NULL && sinfo->unsignedAttrs->list.count > 0) {
		warnx("SignerInfo has at least one unsignedAttr.");
		return -EINVAL;
	}

	/* TODO section 3 */

	return 0;
}

int
signed_data_decode(ANY_t *coded, struct SignedData **result)
{
	struct SignedData *sdata = NULL;
	asn_dec_rval_t rval;
	int error;

	rval = ber_decode(0, &asn_DEF_SignedData, (void **) &sdata, coded->buf,
	    coded->size);
	if (rval.code != RC_OK) {
		warnx("Error decoding signed data object: %d", rval.code);
		/* Must free partial signed data according to API contracts. */
		signed_data_free(sdata);
		return -EINVAL;
	}

	error = validate(sdata);
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
	asn_DEF_SignedData.op->free_struct(&asn_DEF_SignedData, sdata,
	    ASFM_FREE_EVERYTHING);
}
