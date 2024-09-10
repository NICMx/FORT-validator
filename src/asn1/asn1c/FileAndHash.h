/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RPKIManifest"
 * 	found in "rfc6486-a.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#ifndef	_FileAndHash_H_
#define	_FileAndHash_H_

#include "asn1/asn1c/BIT_STRING.h"
#include "asn1/asn1c/IA5String.h"
#include "asn1/asn1c/constr_SEQUENCE.h"

/* FileAndHash */
typedef struct FileAndHash {
	IA5String_t	 file;
	BIT_STRING_t	 hash;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} FileAndHash_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_FileAndHash;
extern asn_SEQUENCE_specifics_t asn_SPC_FileAndHash_specs_1;
extern asn_TYPE_member_t asn_MBR_FileAndHash_1[2];

#endif	/* _FileAndHash_H_ */
