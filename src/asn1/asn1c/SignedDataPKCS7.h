/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "rfc5652-12.1.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#ifndef	_SignedDataPKCS7_H_
#define	_SignedDataPKCS7_H_

#include "asn1/asn1c/CertificateSet.h"
#include "asn1/asn1c/DigestAlgorithmIdentifiers.h"
#include "asn1/asn1c/EncapsulatedContentInfoPKCS7.h"
#include "asn1/asn1c/RevocationInfoChoices.h"
#include "asn1/asn1c/SignerInfos.h"

/* SignedDataPKCS7 */
typedef struct SignedDataPKCS7 {
	CMSVersion_t	 version;
	DigestAlgorithmIdentifiers_t	 digestAlgorithms;
	EncapsulatedContentInfoPKCS7_t	 encapContentInfo;
	struct CertificateSet	*certificates	/* OPTIONAL */;
	struct RevocationInfoChoices	*crls	/* OPTIONAL */;
	SignerInfos_t	 signerInfos;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SignedDataPKCS7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SignedDataPKCS7;

#endif	/* _SignedDataPKCS7_H_ */
