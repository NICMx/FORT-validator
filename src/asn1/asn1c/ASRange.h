/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IPAddrAndASCertExtn"
 * 	found in "rfc3779.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#ifndef	_ASRange_H_
#define	_ASRange_H_

#include "asn1/asn1c/ASId.h"
#include "asn1/asn1c/constr_SEQUENCE.h"

/* ASRange */
typedef struct ASRange {
	ASId_t	 min;
	ASId_t	 max;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ASRange_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ASRange;
extern asn_SEQUENCE_specifics_t asn_SPC_ASRange_specs_1;
extern asn_TYPE_member_t asn_MBR_ASRange_1[2];

#endif	/* _ASRange_H_ */
