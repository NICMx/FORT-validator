/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PKIX1Explicit88"
 * 	found in "rfc5280-a.1.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#ifndef	_AttributeTypeAndValue_H_
#define	_AttributeTypeAndValue_H_

#include "asn1/asn1c/AttributeType.h"
#include "asn1/asn1c/AttributeValue.h"
#include "asn1/asn1c/constr_SEQUENCE.h"

/* AttributeTypeAndValue */
typedef struct AttributeTypeAndValue {
	AttributeType_t	 type;
	AttributeValue_t	 value;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AttributeTypeAndValue_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AttributeTypeAndValue;
extern asn_SEQUENCE_specifics_t asn_SPC_AttributeTypeAndValue_specs_1;
extern asn_TYPE_member_t asn_MBR_AttributeTypeAndValue_1[2];

#endif	/* _AttributeTypeAndValue_H_ */
