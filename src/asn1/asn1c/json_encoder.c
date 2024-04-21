#include "asn1/asn1c/json_encoder.h"

#include "asn1/asn1c/asn_internal.h"

json_t *
json_encode(const asn_TYPE_descriptor_t *td, const void *sptr)
{
	if (!td || !sptr) {
		ASN_DEBUG("Failed to encode element %s", td ? td->name : "");
		return NULL;
	}

	return td->op->json_encoder(td, sptr);
}
