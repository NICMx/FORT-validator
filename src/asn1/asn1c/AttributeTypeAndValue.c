/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PKIX1Explicit88"
 * 	found in "rfc5280-a.1.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#include "asn1/asn1c/AttributeTypeAndValue.h"

asn_TYPE_member_t asn_MBR_AttributeTypeAndValue_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AttributeTypeAndValue, type),
		(ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
		0,
		&asn_DEF_AttributeType,
		NULL,
		{ NULL, NULL, NULL },
		NULL, NULL, /* No default value */
		"type"
		},
	{ ATF_ANY_TYPE | ATF_NOFLAGS, 0, offsetof(struct AttributeTypeAndValue, value),
		-1 /* Ambiguous tag (ANY?) */,
		0,
		&asn_DEF_AttributeValue,
		NULL,
		{ NULL, NULL, NULL },
		NULL, NULL, /* No default value */
		"value"
		},
};
static const ber_tlv_tag_t asn_DEF_AttributeTypeAndValue_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_AttributeTypeAndValue_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 0, 0, 0 } /* type */
};
asn_SEQUENCE_specifics_t asn_SPC_AttributeTypeAndValue_specs_1 = {
	sizeof(struct AttributeTypeAndValue),
	offsetof(struct AttributeTypeAndValue, _asn_ctx),
	asn_MAP_AttributeTypeAndValue_tag2el_1,
	1,	/* Count of tags in the map */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_AttributeTypeAndValue = {
	"AttributeTypeAndValue",
	"AttributeTypeAndValue",
	&asn_OP_SEQUENCE,
	asn_DEF_AttributeTypeAndValue_tags_1,
	sizeof(asn_DEF_AttributeTypeAndValue_tags_1)
		/sizeof(asn_DEF_AttributeTypeAndValue_tags_1[0]), /* 1 */
	asn_DEF_AttributeTypeAndValue_tags_1,	/* Same as above */
	sizeof(asn_DEF_AttributeTypeAndValue_tags_1)
		/sizeof(asn_DEF_AttributeTypeAndValue_tags_1[0]), /* 1 */
	{ NULL, NULL, SEQUENCE_constraint },
	asn_MBR_AttributeTypeAndValue_1,
	2,	/* Elements count */
	&asn_SPC_AttributeTypeAndValue_specs_1	/* Additional specs */
};
