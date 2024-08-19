/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	ASN_TYPE_NULL_H
#define	ASN_TYPE_NULL_H

#include "asn1/asn1c/constraints.h"

/*
 * The value of the NULL type is meaningless.
 * Use the BOOLEAN type if you need to carry true/false semantics.
 */
typedef int NULL_t;

extern asn_TYPE_descriptor_t asn_DEF_NULL;
extern asn_TYPE_operation_t asn_OP_NULL;

asn_struct_free_f NULL_free;
asn_struct_print_f NULL_print;
asn_struct_compare_f NULL_compare;
ber_type_decoder_f NULL_decode_ber;
der_type_encoder_f NULL_encode_der;
json_type_encoder_f NULL_encode_json;
xer_type_encoder_f NULL_encode_xer;

#define NULL_constraint	asn_generic_no_constraint

#endif	/* NULL_H */
