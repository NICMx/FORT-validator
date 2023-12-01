/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PKIX1Explicit88"
 * 	found in "rfc5280-a.1.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#ifndef	_CertificateList_H_
#define	_CertificateList_H_


#include "asn1/asn1c/asn_application.h"

/* Including external dependencies */
#include "asn1/asn1c/TBSCertList.h"
#include "asn1/asn1c/AlgorithmIdentifier.h"
#include "asn1/asn1c/BIT_STRING.h"
#include "asn1/asn1c/constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CertificateList */
typedef struct CertificateList {
	TBSCertList_t	 tbsCertList;
	AlgorithmIdentifier_t	 signatureAlgorithm;
	BIT_STRING_t	 signature;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CertificateList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CertificateList;
extern asn_SEQUENCE_specifics_t asn_SPC_CertificateList_specs_1;
extern asn_TYPE_member_t asn_MBR_CertificateList_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _CertificateList_H_ */
#include "asn1/asn1c/asn_internal.h"
