#include "asn1/asn1c/json_encoder.h"

#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/ber_decoder.h"

json_t *
json_encode(const asn_TYPE_descriptor_t *td, const void *sptr)
{
	if (!td || !sptr) {
		ASN_DEBUG("Failed to encode element %s", td ? td->name : "");
		return NULL;
	}

	return td->op->json_encoder(td, sptr);
}

json_t *
ber2json(struct asn_TYPE_descriptor_s const *td, uint8_t *buf, size_t size)
{
	void *decoded;
	asn_dec_rval_t rval;
	json_t *json;

	decoded = NULL;
	rval = ber_decode(td, &decoded, buf, size);

	json = (rval.code == RC_OK) ? td->op->json_encoder(td, decoded) : NULL;

	ASN_STRUCT_FREE(*td, decoded);
	return json;
}
