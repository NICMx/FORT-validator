/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_CONSTR_SEQUENCE_OF_H_
#define	_CONSTR_SEQUENCE_OF_H_

#include "asn1/asn1c/constr_SET_OF.h"

/*
 * A set specialized functions dealing with the SEQUENCE OF type.
 * Generally implemented using SET OF.
 */
asn_struct_compare_f SEQUENCE_OF_compare;
der_type_encoder_f SEQUENCE_OF_encode_der;
xer_type_encoder_f SEQUENCE_OF_encode_xer;
extern asn_TYPE_operation_t asn_OP_SEQUENCE_OF;

#define	SEQUENCE_OF_free	SET_OF_free
#define	SEQUENCE_OF_print	SET_OF_print
#define	SEQUENCE_OF_constraint	SET_OF_constraint
#define	SEQUENCE_OF_decode_ber	SET_OF_decode_ber
#define	SEQUENCE_OF_encode_json	SET_OF_encode_json

#endif	/* _CONSTR_SET_OF_H_ */
