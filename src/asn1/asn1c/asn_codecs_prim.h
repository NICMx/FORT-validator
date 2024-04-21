/*-
 * Copyright (c) 2004-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	ASN_CODECS_PRIM_H
#define	ASN_CODECS_PRIM_H

#include "asn1/asn1c/asn_application.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ASN__PRIMITIVE_TYPE_s {
    uint8_t *buf;   /* Buffer with consecutive primitive encoding bytes */
    size_t size;    /* Size of the buffer */
} ASN__PRIMITIVE_TYPE_t;	/* Do not use this type directly! */

asn_struct_free_f ASN__PRIMITIVE_TYPE_free;
ber_type_decoder_f ber_decode_primitive;
der_type_encoder_f der_encode_primitive;

#ifdef __cplusplus
}
#endif

#endif	/* ASN_CODECS_PRIM_H */
