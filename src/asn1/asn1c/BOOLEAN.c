/*-
 * Copyright (c) 2003, 2005 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn1/asn1c/BOOLEAN.h"

#include <string.h>

#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/ber_decoder.h"
#include "asn1/asn1c/der_encoder.h"

/*
 * BOOLEAN basic type description.
 */
static const ber_tlv_tag_t asn_DEF_BOOLEAN_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (1 << 2))
};
asn_TYPE_operation_t asn_OP_BOOLEAN = {
	BOOLEAN_free,
	BOOLEAN_print,
	BOOLEAN_compare,
	BOOLEAN_decode_ber,
	BOOLEAN_encode_der,
	BOOLEAN_encode_json,
	BOOLEAN_encode_xer,
	NULL	/* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_BOOLEAN = {
	"BOOLEAN",
	"BOOLEAN",
	&asn_OP_BOOLEAN,
	asn_DEF_BOOLEAN_tags,
	sizeof(asn_DEF_BOOLEAN_tags) / sizeof(asn_DEF_BOOLEAN_tags[0]),
	asn_DEF_BOOLEAN_tags,	/* Same as above */
	sizeof(asn_DEF_BOOLEAN_tags) / sizeof(asn_DEF_BOOLEAN_tags[0]),
	{ NULL, NULL, asn_generic_no_constraint },
	NULL, 0,	/* No members */
	NULL	/* No specifics */
};

/*
 * Decode BOOLEAN type.
 */
asn_dec_rval_t
BOOLEAN_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void **bool_value,
                   const void *buf_ptr, size_t size, int tag_mode) {
    BOOLEAN_t *st = (BOOLEAN_t *)*bool_value;
	asn_dec_rval_t rval;
	ber_tlv_len_t length;
	ber_tlv_len_t lidx;

	if(st == NULL) {
		st = (BOOLEAN_t *)(*bool_value = CALLOC(1, sizeof(*st)));
		if(st == NULL) {
			rval.code = RC_FAIL;
			rval.consumed = 0;
			return rval;
		}
	}

	ASN_DEBUG("Decoding %s as BOOLEAN (tm=%d)",
		td->name, tag_mode);

	/*
	 * Check tags.
	 */
	rval = ber_check_tags(opt_codec_ctx, td, NULL, buf_ptr, size,
		tag_mode, 0, &length, NULL);
	if(rval.code != RC_OK)
		return rval;

	ASN_DEBUG("Boolean length is %d bytes", (int)length);

	buf_ptr = ((const char *)buf_ptr) + rval.consumed;
	size -= rval.consumed;
	if(length > (ber_tlv_len_t)size) {
		rval.code = RC_WMORE;
		rval.consumed = 0;
		return rval;
	}

	/*
	 * Compute boolean value.
	 */
	for(*st = 0, lidx = 0;
		(lidx < length) && *st == 0; lidx++) {
		/*
		 * Very simple approach: read bytes until the end or
		 * value is already TRUE.
		 * BOOLEAN is not supposed to contain meaningful data anyway.
		 */
		*st |= ((const uint8_t *)buf_ptr)[lidx];
	}

	rval.code = RC_OK;
	rval.consumed += length;

	ASN_DEBUG("Took %ld/%ld bytes to encode %s, value=%d",
		(long)rval.consumed, (long)length,
		td->name, *st);
	
	return rval;
}

asn_enc_rval_t
BOOLEAN_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int tag_mode, ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb,
                   void *app_key) {
    asn_enc_rval_t erval;
    const BOOLEAN_t *st = (const BOOLEAN_t *)sptr;

    erval.encoded = der_write_tags(td, 1, tag_mode, 0, tag, cb, app_key);
	if(erval.encoded == -1) {
		erval.failed_type = td;
		erval.structure_ptr = sptr;
		return erval;
	}

	if(cb) {
		uint8_t bool_value;

		bool_value = *st ? 0xff : 0; /* 0xff mandated by DER */

		if(cb(&bool_value, 1, app_key) < 0) {
			erval.encoded = -1;
			erval.failed_type = td;
			erval.structure_ptr = sptr;
			return erval;
		}
	}

	erval.encoded += 1;

	ASN__ENCODED_OK(erval);
}

json_t *
BOOLEAN_encode_json(const struct asn_TYPE_descriptor_s *td, const void *sptr)
{
	const BOOLEAN_t *st = (const BOOLEAN_t *)sptr;
	return (st != NULL) ? json_boolean(*st) : json_null();
}

asn_enc_rval_t
BOOLEAN_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
	int ilevel, int flags, asn_app_consume_bytes_f *cb, void *app_key) {
	const BOOLEAN_t *st = (const BOOLEAN_t *)sptr;
	asn_enc_rval_t er = {0, NULL, NULL};

	(void)ilevel;
	(void)flags;

	if(!st) ASN__ENCODE_FAILED;

	if(*st) {
		ASN__CALLBACK("<true/>", 7);
	} else {
		ASN__CALLBACK("<false/>", 8);
	}

	ASN__ENCODED_OK(er);
cb_failed:
	ASN__ENCODE_FAILED;
}

int
BOOLEAN_print(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
              asn_app_consume_bytes_f *cb, void *app_key) {
    const BOOLEAN_t *st = (const BOOLEAN_t *)sptr;
	const char *buf;
	size_t buflen;

	(void)td;	/* Unused argument */
	(void)ilevel;	/* Unused argument */

	if(st) {
		if(*st) {
			buf = "TRUE";
			buflen = 4;
		} else {
			buf = "FALSE";
			buflen = 5;
		}
	} else {
		buf = "<absent>";
		buflen = 8;
	}

	return (cb(buf, buflen, app_key) < 0) ? -1 : 0;
}

void
BOOLEAN_free(const asn_TYPE_descriptor_t *td, void *ptr,
             enum asn_struct_free_method method) {
    if(td && ptr) {
        switch(method) {
        case ASFM_FREE_EVERYTHING:
            FREEMEM(ptr);
            break;
        case ASFM_FREE_UNDERLYING:
            break;
        case ASFM_FREE_UNDERLYING_AND_RESET:
            memset(ptr, 0, sizeof(BOOLEAN_t));
            break;
        }
    }
}

int
BOOLEAN_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
                const void *bptr) {
    const BOOLEAN_t *a = aptr;
    const BOOLEAN_t *b = bptr;

    (void)td;

    if(a && b) {
        if(!*a == !*b) {    /* TRUE can be encoded by any non-zero byte. */
            return 0;
        } else if(!*a) {
            return -1;
        } else {
            return 1;
        }
    } else if(!a) {
        return -1;
    } else {
        return 1;
    }
}
