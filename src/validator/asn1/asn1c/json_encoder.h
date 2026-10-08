#ifndef VALIDATOR_ASN1_ASN1C_JSON_ENCODER_H_
#define VALIDATOR_ASN1_ASN1C_JSON_ENCODER_H_

#include "validator/asn1/asn1c/constr_TYPE.h"

json_t *json_encode(
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const void *struct_ptr /* Structure to be encoded */
);

json_t *ber2json(struct asn_TYPE_descriptor_s const *, uint8_t *, size_t);

#endif /* VALIDATOR_ASN1_ASN1C_JSON_ENCODER_H_ */
