/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IPAddrAndASCertExtn"
 * 	found in "rfc3779.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#include "asn1/asn1c/ASId.h"

/*
 * This type is implemented using INTEGER,
 * so here we adjust the DEF accordingly.
 */
static const ber_tlv_tag_t asn_DEF_ASId_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (2 << 2))
};
asn_TYPE_descriptor_t asn_DEF_ASId = {
	"ASId",
	"ASId",
	&asn_OP_INTEGER,
	asn_DEF_ASId_tags_1,
	sizeof(asn_DEF_ASId_tags_1)
		/sizeof(asn_DEF_ASId_tags_1[0]), /* 1 */
	asn_DEF_ASId_tags_1,	/* Same as above */
	sizeof(asn_DEF_ASId_tags_1)
		/sizeof(asn_DEF_ASId_tags_1[0]), /* 1 */
	{ NULL, NULL, INTEGER_constraint },
	NULL, 0,	/* No members */
	NULL	/* No specifics */
};
