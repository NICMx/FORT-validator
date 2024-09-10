#ifndef SRC_ASN1_ASN1C_JSON_ENCODER_H_
#define SRC_ASN1_ASN1C_JSON_ENCODER_H_

#include "asn1/asn1c/constr_TYPE.h"

json_t *json_encode(
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const void *struct_ptr /* Structure to be encoded */
);

json_t *ber2json(struct asn_TYPE_descriptor_s const *, uint8_t *, size_t);

#endif /* SRC_ASN1_ASN1C_JSON_ENCODER_H_ */
