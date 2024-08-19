/*-
 * Copyright (c) 2017-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef ASN_OPEN_TYPE_H
#define ASN_OPEN_TYPE_H

#include "asn1/asn1c/constr_CHOICE.h"

#define OPEN_TYPE_free CHOICE_free
#define OPEN_TYPE_print CHOICE_print
#define OPEN_TYPE_compare CHOICE_compare
#define OPEN_TYPE_constraint CHOICE_constraint
#define OPEN_TYPE_decode_ber NULL
#define OPEN_TYPE_encode_der CHOICE_encode_der
#define OPEN_TYPE_encode_json CHOICE_encode_json
#define OPEN_TYPE_encode_xer CHOICE_encode_xer

extern asn_TYPE_operation_t asn_OP_OPEN_TYPE;

/*
 * Decode an Open Type which is potentially constraiend
 * by the other members of the parent structure.
 */
asn_dec_rval_t OPEN_TYPE_ber_get(const asn_codec_ctx_t *opt_codec_ctx,
                                 const asn_TYPE_descriptor_t *parent_type,
                                 void *parent_structure,
                                 const asn_TYPE_member_t *element,
                                 const void *ptr, size_t size);

#endif	/* ASN_OPEN_TYPE_H */
