#include "signed_object.h"

#include <errno.h>
#include "log.h"
#include "asn1/content_info.h"
#include "asn1/decode.h"

static int
validate_eContentType(struct SignedData *sdata,
    asn_TYPE_descriptor_t const *descriptor,
    struct oid_arcs const *oid)
{
	struct oid_arcs arcs;
	bool equals;
	int error;

	error = oid2arcs(&sdata->encapContentInfo.eContentType, &arcs);
	if (error)
		return error;
	equals = arcs_equal(&arcs, oid);
	free_arcs(&arcs);
	if (!equals) {
		return pr_err("SignedObject's encapContentInfo lacks the OID of a %s.",
		    descriptor->name);
	}

	return 0;
}

static int
validate_content_type(struct SignedData *sdata,
    asn_TYPE_descriptor_t const *descriptor,
    struct oid_arcs const *oid)
{
	OBJECT_IDENTIFIER_t *ctype;
	struct oid_arcs arcs;
	bool equals;
	int error;

	error = get_content_type_attr(sdata, &ctype);
	if (error)
		return error;
	error = oid2arcs(ctype, &arcs);
	ASN_STRUCT_FREE(asn_DEF_OBJECT_IDENTIFIER, ctype);
	if (error)
		return error;
	equals = arcs_equal(&arcs, oid);
	free_arcs(&arcs);
	if (!equals) {
		return pr_err("SignedObject's content type attribute lacks the OID of a %s.",
		    descriptor->name);
	}

	return 0;
}

int
signed_object_decode(struct signed_object_args *args,
    asn_TYPE_descriptor_t const *descriptor,
    struct oid_arcs const *oid,
    void **result)
{
	struct ContentInfo *cinfo;
	struct SignedData *sdata;
	int error;

	error = content_info_load(args->uri, &cinfo);
	if (error)
		goto end1;

	error = signed_data_decode(&cinfo->content, args, &sdata);
	if (error)
		goto end2;

	/* rfc6482#section-2 */
	/* rfc6486#section-4.1 */
	/* rfc6486#section-4.4.1 */
	error = validate_eContentType(sdata, descriptor, oid);
	if (error)
		goto end3;

	/* rfc6482#section-2 */
	/* rfc6486#section-4.3 */
	error = validate_content_type(sdata, descriptor, oid);
	if (error)
		goto end3;

	error = asn1_decode_octet_string(sdata->encapContentInfo.eContent,
	    descriptor, result);

end3:	signed_data_free(sdata);
end2:	content_info_free(cinfo);
end1:	return error;
}
