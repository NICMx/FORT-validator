/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RPKIManifest"
 * 	found in "rfc6486-a.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#include "asn1/asn1c/Manifest.h"

#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/constr_SEQUENCE_OF.h"

static int
memb_manifestNumber_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const INTEGER_t *st = (const INTEGER_t *)sptr;
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Check if the sign bit is present */
	value = st->buf ? ((st->buf[0] & 0x80) ? -1 : 1) : 0;
	
	if((value >= 0)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_fileList_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	
	if(1 /* No applicable constraints whatsoever */) {
		/* Nothing is here. See below */
	}
	
	return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
}

static int asn_DFL_2_cmp_0(const void *sptr) {
	const INTEGER_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 0 */
	long value;
	if(asn_INTEGER2long(st, &value))
		return -1;
	return (value != 0);
}
static int asn_DFL_2_set_0(void **sptr) {
	INTEGER_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 0 */
	return asn_long2INTEGER(st, 0);
}
static asn_TYPE_member_t asn_MBR_fileList_7[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_FileAndHash,
		NULL,
		{ NULL, NULL, NULL },
		NULL, NULL, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_fileList_tags_7[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_fileList_specs_7 = {
	sizeof(struct Manifest__fileList),
	offsetof(struct Manifest__fileList, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fileList_7 = {
	"fileList",
	"fileList",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_fileList_tags_7,
	sizeof(asn_DEF_fileList_tags_7)
		/sizeof(asn_DEF_fileList_tags_7[0]), /* 1 */
	asn_DEF_fileList_tags_7,	/* Same as above */
	sizeof(asn_DEF_fileList_tags_7)
		/sizeof(asn_DEF_fileList_tags_7[0]), /* 1 */
	{ NULL, NULL, SEQUENCE_OF_constraint },
	asn_MBR_fileList_7,
	1,	/* Single element */
	&asn_SPC_fileList_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_Manifest_1[] = {
	{ ATF_POINTER, 1, offsetof(struct Manifest, version),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_INTEGER,
		NULL,
		{ NULL, NULL, NULL },
		&asn_DFL_2_cmp_0,	/* Compare DEFAULT 0 */
		&asn_DFL_2_set_0,	/* Set DEFAULT 0 */
		"version"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Manifest, manifestNumber),
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_INTEGER,
		NULL,
		{ NULL, NULL,  memb_manifestNumber_constraint_1 },
		NULL, NULL, /* No default value */
		"manifestNumber"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Manifest, thisUpdate),
		(ASN_TAG_CLASS_UNIVERSAL | (24 << 2)),
		0,
		&asn_DEF_GeneralizedTime,
		NULL,
		{ NULL, NULL, NULL },
		NULL, NULL, /* No default value */
		"thisUpdate"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Manifest, nextUpdate),
		(ASN_TAG_CLASS_UNIVERSAL | (24 << 2)),
		0,
		&asn_DEF_GeneralizedTime,
		NULL,
		{ NULL, NULL, NULL },
		NULL, NULL, /* No default value */
		"nextUpdate"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Manifest, fileHashAlg),
		(ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
		0,
		&asn_DEF_OBJECT_IDENTIFIER,
		NULL,
		{ NULL, NULL, NULL },
		NULL, NULL, /* No default value */
		"fileHashAlg"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Manifest, fileList),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_fileList_7,
		NULL,
		{ NULL, NULL,  memb_fileList_constraint_1 },
		NULL, NULL, /* No default value */
		"fileList"
		},
};
static const ber_tlv_tag_t asn_DEF_Manifest_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Manifest_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, 0, 0 }, /* manifestNumber */
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 4, 0, 0 }, /* fileHashAlg */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 5, 0, 0 }, /* fileList */
    { (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)), 2, 0, 1 }, /* thisUpdate */
    { (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)), 3, -1, 0 }, /* nextUpdate */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* version */
};
static asn_SEQUENCE_specifics_t asn_SPC_Manifest_specs_1 = {
	sizeof(struct Manifest),
	offsetof(struct Manifest, _asn_ctx),
	asn_MAP_Manifest_tag2el_1,
	6,	/* Count of tags in the map */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Manifest = {
	"Manifest",
	"Manifest",
	&asn_OP_SEQUENCE,
	asn_DEF_Manifest_tags_1,
	sizeof(asn_DEF_Manifest_tags_1)
		/sizeof(asn_DEF_Manifest_tags_1[0]), /* 1 */
	asn_DEF_Manifest_tags_1,	/* Same as above */
	sizeof(asn_DEF_Manifest_tags_1)
		/sizeof(asn_DEF_Manifest_tags_1[0]), /* 1 */
	{ NULL, NULL, SEQUENCE_constraint },
	asn_MBR_Manifest_1,
	6,	/* Elements count */
	&asn_SPC_Manifest_specs_1	/* Additional specs */
};
