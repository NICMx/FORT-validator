/*-
 * Copyright (c) 2003 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/IA5String.h"

/*
 * IA5String basic type description.
 */
static const ber_tlv_tag_t asn_DEF_IA5String_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (22 << 2)),	/* [UNIVERSAL 22] IMPLICIT ...*/
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))	/* ... OCTET STRING */
};
asn_TYPE_operation_t asn_OP_IA5String = {
	OCTET_STRING_free,
	OCTET_STRING_print_utf8,	/* ASCII subset */
	OCTET_STRING_compare,
	OCTET_STRING_decode_ber,    /* Implemented in terms of OCTET STRING */
	OCTET_STRING_encode_der,
	OCTET_STRING_encode_xer_utf8,
	0	/* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_IA5String = {
	"IA5String",
	"IA5String",
	&asn_OP_IA5String,
	asn_DEF_IA5String_tags,
	sizeof(asn_DEF_IA5String_tags)
	  / sizeof(asn_DEF_IA5String_tags[0]) - 1,
	asn_DEF_IA5String_tags,
	sizeof(asn_DEF_IA5String_tags)
	  / sizeof(asn_DEF_IA5String_tags[0]),
	{ 0, NULL, IA5String_constraint },
	0, 0,	/* No members */
	0	/* No specifics */
};

int
IA5String_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                     asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    const IA5String_t *st = (const IA5String_t *)sptr;

	if(st && st->buf) {
		uint8_t *buf = st->buf;
		uint8_t *end = buf + st->size;
		/*
		 * IA5String is generally equivalent to 7bit ASCII.
		 * ISO/ITU-T T.50, 1963.
		 */
		for(; buf < end; buf++) {
			if(*buf > 0x7F) {
				ASN__CTFAIL(app_key, td, sptr,
					"%s: value byte %ld out of range: "
					"%d > 127 (%s:%d)",
					td->name,
					(long)((buf - st->buf) + 1),
					*buf,
					__FILE__, __LINE__);
				return -1;
			}
		}
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}

	return 0;
}
