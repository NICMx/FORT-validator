#ifndef SRC_ASN1_ASN1C_JSON_ENCODER_H_
#define SRC_ASN1_ASN1C_JSON_ENCODER_H_

#include <jansson.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

struct asn_TYPE_descriptor_s;	/* Forward declaration */

json_t *json_encode(
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const void *struct_ptr /* Structure to be encoded */
);

json_t *ber2json(struct asn_TYPE_descriptor_s const *, uint8_t *, size_t);

#endif /* SRC_ASN1_ASN1C_JSON_ENCODER_H_ */
