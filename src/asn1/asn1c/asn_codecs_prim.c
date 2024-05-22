/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn1/asn1c/asn_codecs_prim.h"

#include <assert.h>

#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/ber_decoder.h"
#include "asn1/asn1c/der_encoder.h"

/*
 * Decode an always-primitive type.
 */
asn_dec_rval_t
ber_decode_primitive(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td, void **sptr,
                     const void *buf_ptr, size_t size, int tag_mode) {
    ASN__PRIMITIVE_TYPE_t *st = (ASN__PRIMITIVE_TYPE_t *)*sptr;
	asn_dec_rval_t rval;
	ber_tlv_len_t length = 0; /* =0 to avoid [incorrect] warning. */

	/*
	 * If the structure is not there, allocate it.
	 */
	if(st == NULL) {
		st = (ASN__PRIMITIVE_TYPE_t *)CALLOC(1, sizeof(*st));
		if(st == NULL) ASN__DECODE_FAILED;
		*sptr = (void *)st;
	}

	ASN_DEBUG("Decoding %s as plain primitive (tm=%d)",
		td->name, tag_mode);

	/*
	 * Check tags and extract value length.
	 */
	rval = ber_check_tags(opt_codec_ctx, td, 0, buf_ptr, size,
			tag_mode, 0, &length, 0);
	if(rval.code != RC_OK)
		return rval;

	ASN_DEBUG("%s length is %d bytes", td->name, (int)length);

	/*
	 * Make sure we have this length.
	 */
	buf_ptr = ((const char *)buf_ptr) + rval.consumed;
	size -= rval.consumed;
	if(length > (ber_tlv_len_t)size) {
		rval.code = RC_WMORE;
		rval.consumed = 0;
		return rval;
	}

	st->size = (int)length;
	/* The following better be optimized away. */
	if(sizeof(st->size) != sizeof(length)
			&& (ber_tlv_len_t)st->size != length) {
		st->size = 0;
		ASN__DECODE_FAILED;
	}

	st->buf = (uint8_t *)MALLOC(length + 1);
	if(!st->buf) {
		st->size = 0;
		ASN__DECODE_FAILED;
	}

	memcpy(st->buf, buf_ptr, length);
	st->buf[length] = '\0';		/* Just in case */

	rval.code = RC_OK;
	rval.consumed += length;

	ASN_DEBUG("Took %ld/%ld bytes to encode %s",
		(long)rval.consumed,
		(long)length, td->name);

	return rval;
}

/*
 * Encode an always-primitive type using DER.
 */
asn_enc_rval_t
der_encode_primitive(const asn_TYPE_descriptor_t *td, const void *sptr,
                     int tag_mode, ber_tlv_tag_t tag,
                     asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t erval;
	const ASN__PRIMITIVE_TYPE_t *st = (const ASN__PRIMITIVE_TYPE_t *)sptr;

	ASN_DEBUG("%s %s as a primitive type (tm=%d)",
		cb?"Encoding":"Estimating", td->name, tag_mode);

	erval.encoded = der_write_tags(td, st->size, tag_mode, 0, tag,
		cb, app_key);
	ASN_DEBUG("%s wrote tags %d", td->name, (int)erval.encoded);
	if(erval.encoded == -1) {
		erval.failed_type = td;
		erval.structure_ptr = sptr;
		return erval;
	}

	if(cb && st->buf) {
		if(cb(st->buf, st->size, app_key) < 0) {
			erval.encoded = -1;
			erval.failed_type = td;
			erval.structure_ptr = sptr;
			return erval;
		}
	} else {
		assert(st->buf || st->size == 0);
	}

	erval.encoded += st->size;
	ASN__ENCODED_OK(erval);
}

void
ASN__PRIMITIVE_TYPE_free(const asn_TYPE_descriptor_t *td, void *sptr,
                         enum asn_struct_free_method method) {
    ASN__PRIMITIVE_TYPE_t *st = (ASN__PRIMITIVE_TYPE_t *)sptr;

	if(!td || !sptr)
		return;

	ASN_DEBUG("Freeing %s as a primitive type", td->name);

	if(st->buf)
		FREEMEM(st->buf);

    switch(method) {
    case ASFM_FREE_EVERYTHING:
        FREEMEM(sptr);
        break;
    case ASFM_FREE_UNDERLYING:
        break;
    case ASFM_FREE_UNDERLYING_AND_RESET:
        memset(sptr, 0, sizeof(ASN__PRIMITIVE_TYPE_t));
        break;
    }
}
