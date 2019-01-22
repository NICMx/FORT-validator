#include "content_info.h"

#include <errno.h>
#include <libcmscodec/ContentType.h>
#include "file.h"
#include "oid.h"
#include "asn1/decode.h"

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

	if (!ARCS_EQUAL_OIDS(&arcs, oid_sdata)) {
		fprintf(stderr, "Incorrect content-type.");
		return -EINVAL;
	}

	return 0;
}

static int
decode(struct file_contents *fc, struct ContentInfo **result)
{
	struct ContentInfo *cinfo;
	int error;

	error = asn1_decode_fc(fc, &asn_DEF_ContentInfo, (void **) &cinfo);
	if (error)
		return error;

	error = validate(cinfo);
	if (error) {
		content_info_free(cinfo);
		return error;
	}

	*result = cinfo;
	return 0;
}

int
content_info_load(struct rpki_uri const *uri, struct ContentInfo **result)
{
	struct file_contents fc;
	int error;

	error = file_load(uri, &fc);
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
