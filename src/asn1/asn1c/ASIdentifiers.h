/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IPAddrAndASCertExtn"
 * 	found in "rfc3779.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#ifndef	_ASIdentifiers_H_
#define	_ASIdentifiers_H_

#include "asn1/asn1c/ASIdentifierChoice.h"

/* ASIdentifiers */
typedef struct ASIdentifiers {
	struct ASIdentifierChoice	*asnum	/* OPTIONAL */;
	struct ASIdentifierChoice	*rdi	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ASIdentifiers_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ASIdentifiers;

#endif	/* _ASIdentifiers_H_ */
