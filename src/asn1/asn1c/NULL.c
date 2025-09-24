/*-
 * Copyright (c) 2003, 2005 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn1/asn1c/NULL.h"

#include <string.h>

#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/ber_decoder.h"
#include "asn1/asn1c/der_encoder.h"

/*
 * NULL basic type description.
 */
static const ber_tlv_tag_t asn_DEF_NULL_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (5 << 2))
};
asn_TYPE_operation_t asn_OP_NULL = {
	NULL_free,
	NULL_print,
	NULL_compare,
	NULL_decode_ber,
	NULL_encode_der,	/* Special handling of DER encoding */
	NULL_encode_json,
	NULL_encode_xer,
	NULL	/* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_NULL = {
	"NULL",
	"NULL",
	&asn_OP_NULL,
	asn_DEF_NULL_tags,
	sizeof(asn_DEF_NULL_tags) / sizeof(asn_DEF_NULL_tags[0]),
	asn_DEF_NULL_tags,	/* Same as above */
	sizeof(asn_DEF_NULL_tags) / sizeof(asn_DEF_NULL_tags[0]),
	{ NULL, NULL, asn_generic_no_constraint },
	NULL, 0,	/* No members */
	NULL	/* No specifics */
};

void
NULL_free(const asn_TYPE_descriptor_t *td, void *ptr,
          enum asn_struct_free_method method) {
    if(td && ptr) {
        switch(method) {
        case ASFM_FREE_EVERYTHING:
            FREEMEM(ptr);
            break;
        case ASFM_FREE_UNDERLYING:
            break;
        case ASFM_FREE_UNDERLYING_AND_RESET:
            memset(ptr, 0, sizeof(NULL_t));
            break;
        }
    }
}

/*
 * Decode NULL type.
 */
asn_dec_rval_t
NULL_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td, void **bool_value,
                const void *buf_ptr, size_t size, int tag_mode) {
    NULL_t *st = (NULL_t *)*bool_value;
    asn_dec_rval_t rval;
    ber_tlv_len_t length;

    if(st == NULL) {
        st = (NULL_t *)(*bool_value = CALLOC(1, sizeof(*st)));
        if(st == NULL) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    }

    ASN_DEBUG("Decoding %s as NULL (tm=%d)", td->name, tag_mode);

    /*
     * Check tags.
     */
    rval = ber_check_tags(opt_codec_ctx, td, NULL, buf_ptr, size, tag_mode, 0,
                          &length, NULL);
    if(rval.code != RC_OK) {
        return rval;
    }

    // X.690-201508, #8.8.2, length shall be zero.
    if(length != 0) {
        ASN_DEBUG("Decoding %s as NULL failed: too much data", td->name);
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    return rval;
}

asn_enc_rval_t
NULL_encode_der(const asn_TYPE_descriptor_t *td, const void *ptr, int tag_mode,
                ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t erval;

	erval.encoded = der_write_tags(td, 0, tag_mode, 0, tag, cb, app_key);
	if(erval.encoded == -1) {
		erval.failed_type = td;
		erval.structure_ptr = ptr;
	}

	ASN__ENCODED_OK(erval);
}

json_t *
NULL_encode_json(const struct asn_TYPE_descriptor_s *td, const void *sptr)
{
	return json_null();
}

asn_enc_rval_t
NULL_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
                int flags, asn_app_consume_bytes_f *cb,
                void *app_key) {
    asn_enc_rval_t er;

	(void)td;
	(void)sptr;
	(void)ilevel;
	(void)flags;
	(void)cb;
	(void)app_key;

	/* XMLNullValue is empty */
	er.encoded = 0;
	ASN__ENCODED_OK(er);
}

int
NULL_compare(const asn_TYPE_descriptor_t *td, const void *a, const void *b) {
    (void)td;
    (void)a;
    (void)b;
    return 0;
}

int
NULL_print(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
           asn_app_consume_bytes_f *cb, void *app_key) {
    (void)td;	/* Unused argument */
	(void)ilevel;	/* Unused argument */

	if(sptr) {
		return (cb("<present>", 9, app_key) < 0) ? -1 : 0;
	} else {
		return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;
	}
}
