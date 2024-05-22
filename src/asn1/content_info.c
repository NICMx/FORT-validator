#include "asn1/content_info.h"

#include "asn1/asn1c/ContentType.h"
#include "asn1/decode.h"
#include "asn1/oid.h"
#include "file.h"
#include "log.h"

static int
validate(struct ContentInfo *info)
{
	static const OID oid_sdata = OID_SIGNED_DATA;
	struct oid_arcs arcs;
	int error;

	/* rfc6488#section-2 */
	/* rfc6488#section-3.1.a */
	error = oid2arcs(&info->contentType, &arcs);
	if (error)
		return error;

	if (!ARCS_EQUAL_OIDS(&arcs, oid_sdata))
		error = pr_val_err("Incorrect content-type.");

	free_arcs(&arcs);
	return error;
}

static int
decode(struct file_contents *fc, struct ContentInfo **result)
{
	struct ContentInfo *cinfo;
	int error;

	error = asn1_decode_fc(fc, &asn_DEF_ContentInfo, (void **) &cinfo,
	    true);
	if (error)
		return error;

	/* TODO (asn1c) rfc6488#3.1.l: Validate DER encoding */

	error = validate(cinfo);
	if (error) {
		content_info_free(cinfo);
		return error;
	}

	*result = cinfo;
	return 0;
}

int
content_info_load(char const *file, struct ContentInfo **result)
{
	struct file_contents fc;
	int error;

	error = file_load(file, &fc);
	if (error)
		return error;

	error = decode(&fc, result);

	file_free(&fc);
	return error;
}

void
content_info_free(struct ContentInfo *info)
{
	ASN_STRUCT_FREE(asn_DEF_ContentInfo, info);
}
