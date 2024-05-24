/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RPKI-ROA"
 * 	found in "rfc6482.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#ifndef	_RouteOriginAttestation_H_
#define	_RouteOriginAttestation_H_

#include "asn1/asn1c/ASId.h"
#include "asn1/asn1c/INTEGER.h"
#include "asn1/asn1c/ROAIPAddressFamily.h"
#include "asn1/asn1c/asn_SEQUENCE_OF.h"
#include "asn1/asn1c/constr_SEQUENCE.h"
#include "asn1/asn1c/constr_SEQUENCE_OF.h"
#include "asn1/asn1c/constr_TYPE.h"

/* Forward declarations */
struct ROAIPAddressFamily;

/* RouteOriginAttestation */
typedef struct RouteOriginAttestation {
	INTEGER_t	*version	/* DEFAULT 0 */;
	ASId_t	 asId;
	struct RouteOriginAttestation__ipAddrBlocks {
		A_SEQUENCE_OF(struct ROAIPAddressFamily) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} ipAddrBlocks;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RouteOriginAttestation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RouteOriginAttestation;

#endif	/* _RouteOriginAttestation_H_ */
