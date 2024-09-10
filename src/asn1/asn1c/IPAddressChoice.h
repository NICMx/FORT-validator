/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IPAddrAndASCertExtn"
 * 	found in "rfc3779.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#ifndef	_IPAddressChoice_H_
#define	_IPAddressChoice_H_

#include "asn1/asn1c/IPAddressOrRange.h"
#include "asn1/asn1c/NULL.h"
#include "asn1/asn1c/asn_SEQUENCE_OF.h"

/* Dependencies */
typedef enum IPAddressChoice_PR {
	IPAddressChoice_PR_NOTHING,	/* No components present */
	IPAddressChoice_PR_inherit,
	IPAddressChoice_PR_addressesOrRanges
} IPAddressChoice_PR;

/* IPAddressChoice */
typedef struct IPAddressChoice {
	IPAddressChoice_PR present;
	union IPAddressChoice_u {
		NULL_t	 inherit;
		struct IPAddressChoice__addressesOrRanges {
			A_SEQUENCE_OF(struct IPAddressOrRange) list;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} addressesOrRanges;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IPAddressChoice_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IPAddressChoice;
extern asn_CHOICE_specifics_t asn_SPC_IPAddressChoice_specs_1;
extern asn_TYPE_member_t asn_MBR_IPAddressChoice_1[2];

#endif	/* _IPAddressChoice_H_ */
