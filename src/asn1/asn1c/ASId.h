/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IPAddrAndASCertExtn"
 * 	found in "rfc3779.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#ifndef	_ASId_H_
#define	_ASId_H_

#include "asn1/asn1c/INTEGER.h"

/* ASId */
typedef INTEGER_t	 ASId_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ASId;
asn_struct_free_f ASId_free;
asn_struct_print_f ASId_print;
asn_constr_check_f ASId_constraint;
ber_type_decoder_f ASId_decode_ber;
der_type_encoder_f ASId_encode_der;
xer_type_encoder_f ASId_encode_xer;

#endif	/* _ASId_H_ */
