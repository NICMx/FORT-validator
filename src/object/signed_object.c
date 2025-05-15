#include "object/signed_object.h"

#include "asn1/content_info.h"
#include "asn1/signed_data.h"
#include "log.h"

int
signed_object_decode(struct signed_object *so, struct cache_mapping const *map)
{
	int error;

	so->map = map;

	error = content_info_load(map->path, &so->cinfo);
	if (error)
		return error;

	error = signed_data_decode(&so->cinfo->content, &so->sdata);
	if (error) {
		content_info_free(so->cinfo);
		return error;
	}

	return 0;
}

static int
validate_eContentType(struct SignedData *sdata, struct oid_arcs const *oid)
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
		return pr_val_err("The OID of the SignedObject's encapContentInfo is not '%s'.",
		    oid->name);
	}

	return 0;
}

static int
validate_content_type(struct SignedData *sdata, struct oid_arcs const *oid)
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
		return pr_val_err("The OID of the SignedObject's content type attribute is not '%s'.",
		    oid->name);
	}

	return 0;
}

int
signed_object_validate(struct signed_object *so, struct rpki_certificate *ee,
    struct oid_arcs const *oid)
{
	int error;

	/* rfc6482#section-2 */
	/* rfc6486#section-4.1 */
	/* rfc6486#section-4.4.1 */
	error = validate_eContentType(so->sdata, oid);
	if (error)
		return error;

	/* rfc6482#section-2 */
	/* rfc6486#section-4.3 */
	error = validate_content_type(so->sdata, oid);
	if (error)
		return error;

	return signed_data_validate(so, ee);
}

void
signed_object_cleanup(struct signed_object *so)
{
	content_info_free(so->cinfo);
	ASN_STRUCT_FREE(asn_DEF_SignedData, so->sdata);
}
