/*-
 * Copyright (c) 2003, 2004, 2006 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn1/asn1c/constr_SEQUENCE_OF.h"

#include "asn1/asn1c/asn_SEQUENCE_OF.h"
#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/der_encoder.h"
#include "asn1/asn1c/xer_encoder.h"

/*
 * The DER encoder of the SEQUENCE OF type.
 */
asn_enc_rval_t
SEQUENCE_OF_encode_der(const asn_TYPE_descriptor_t *td, const void *ptr,
                       int tag_mode, ber_tlv_tag_t tag,
                       asn_app_consume_bytes_f *cb, void *app_key) {
    asn_TYPE_member_t *elm = td->elements;
	const asn_anonymous_sequence_ *list = _A_CSEQUENCE_FROM_VOID(ptr);
	size_t computed_size = 0;
	ssize_t encoding_size = 0;
	asn_enc_rval_t erval;
	int edx;

	ASN_DEBUG("Estimating size of SEQUENCE OF %s", td->name);

	/*
	 * Gather the length of the underlying members sequence.
	 */
	for(edx = 0; edx < list->count; edx++) {
		void *memb_ptr = list->array[edx];
		if(!memb_ptr) continue;
		erval = elm->type->op->der_encoder(elm->type, memb_ptr,
			0, elm->tag,
			0, 0);
		if(erval.encoded == -1)
			return erval;
		computed_size += erval.encoded;
	}

	/*
	 * Encode the TLV for the sequence itself.
	 */
	encoding_size = der_write_tags(td, computed_size, tag_mode, 1, tag,
		cb, app_key);
	if(encoding_size == -1) {
		erval.encoded = -1;
		erval.failed_type = td;
		erval.structure_ptr = ptr;
		return erval;
	}

	computed_size += encoding_size;
	if(!cb) {
		erval.encoded = computed_size;
		ASN__ENCODED_OK(erval);
	}

	ASN_DEBUG("Encoding members of SEQUENCE OF %s", td->name);

	/*
	 * Encode all members.
	 */
	for(edx = 0; edx < list->count; edx++) {
		void *memb_ptr = list->array[edx];
		if(!memb_ptr) continue;
		erval = elm->type->op->der_encoder(elm->type, memb_ptr,
			0, elm->tag,
			cb, app_key);
		if(erval.encoded == -1)
			return erval;
		encoding_size += erval.encoded;
	}

	if(computed_size != (size_t)encoding_size) {
		/*
		 * Encoded size is not equal to the computed size.
		 */
		erval.encoded = -1;
		erval.failed_type = td;
		erval.structure_ptr = ptr;
	} else {
		erval.encoded = computed_size;
		erval.structure_ptr = 0;
		erval.failed_type = 0;
	}

	return erval;
}

asn_enc_rval_t
SEQUENCE_OF_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                       int ilevel, int flags,
                       asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er;
    const asn_SET_OF_specifics_t *specs = (const asn_SET_OF_specifics_t *)td->specifics;
    const asn_TYPE_member_t *elm = td->elements;
    const asn_anonymous_sequence_ *list = _A_CSEQUENCE_FROM_VOID(sptr);
    const char *mname = specs->as_XMLValueList
                            ? 0
                            : ((*elm->name) ? elm->name : elm->type->xml_tag);
    size_t mlen = mname ? strlen(mname) : 0;
    int xcan = (flags & XER_F_CANONICAL);
    int i;

    if(!sptr) ASN__ENCODE_FAILED;

    er.encoded = 0;

    for(i = 0; i < list->count; i++) {
        asn_enc_rval_t tmper;
        void *memb_ptr = list->array[i];
        if(!memb_ptr) continue;

        if(mname) {
            if(!xcan) ASN__TEXT_INDENT(1, ilevel);
            ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);
        }

        tmper = elm->type->op->xer_encoder(elm->type, memb_ptr, ilevel + 1,
                                           flags, cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;
        if(tmper.encoded == 0 && specs->as_XMLValueList) {
            const char *name = elm->type->xml_tag;
            size_t len = strlen(name);
            if(!xcan) ASN__TEXT_INDENT(1, ilevel + 1);
            ASN__CALLBACK3("<", 1, name, len, "/>", 2);
        }

        if(mname) {
            ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
        }
    }

    if(!xcan) ASN__TEXT_INDENT(1, ilevel - 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

int
SEQUENCE_OF_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
               const void *bptr) {
    const asn_anonymous_sequence_ *a = _A_CSEQUENCE_FROM_VOID(aptr);
    const asn_anonymous_sequence_ *b = _A_CSEQUENCE_FROM_VOID(bptr);
    ssize_t idx;

    if(a && b) {
        ssize_t common_length = (a->count < b->count ? a->count : b->count);
        for(idx = 0; idx < common_length; idx++) {
            int ret = td->elements->type->op->compare_struct(
                td->elements->type, a->array[idx], b->array[idx]);
            if(ret) return ret;
        }

        if(idx < b->count) /* more elements in b */
            return -1;    /* a is shorter, so put it first */
        if(idx < a->count) return 1;

    } else if(!a) {
        return -1;
    } else if(!b) {
        return 1;
    }

    return 0;
}


asn_TYPE_operation_t asn_OP_SEQUENCE_OF = {
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_compare,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_encode_json,
	SEQUENCE_OF_encode_xer,
	0	/* Use generic outmost tag fetcher */
};
