/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "rfc5652-12.1.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#ifndef	_UnsignedAttributes_H_
#define	_UnsignedAttributes_H_

#include "asn1/asn1c/CMSAttribute.h"
#include "asn1/asn1c/constr_SET_OF.h"

/* UnsignedAttributes */
typedef struct UnsignedAttributes {
	A_SET_OF(struct CMSAttribute) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UnsignedAttributes_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UnsignedAttributes;
extern asn_SET_OF_specifics_t asn_SPC_UnsignedAttributes_specs_1;
extern asn_TYPE_member_t asn_MBR_UnsignedAttributes_1[1];

#endif	/* _UnsignedAttributes_H_ */
