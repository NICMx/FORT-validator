/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "asn1/asn1c/constr_SET_OF.h"

#include <assert.h>

#include "asn1/asn1c/asn_SET_OF.h"
#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/ber_decoder.h"
#include "asn1/asn1c/constraints.h"
#include "asn1/asn1c/der_encoder.h"
#include "asn1/asn1c/xer_encoder.h"
#include "json_util.h"

/*
 * Number of bytes left for this structure.
 * (ctx->left) indicates the number of bytes _transferred_ for the structure.
 * (size) contains the number of bytes in the buffer passed.
 */
#define	LEFT	((size<(size_t)ctx->left)?size:(size_t)ctx->left)

/*
 * If the subprocessor function returns with an indication that it wants
 * more data, it may well be a fatal decoding problem, because the
 * size is constrained by the <TLV>'s L, even if the buffer size allows
 * reading more data.
 * For example, consider the buffer containing the following TLVs:
 * <T:5><L:1><V> <T:6>...
 * The TLV length clearly indicates that one byte is expected in V, but
 * if the V processor returns with "want more data" even if the buffer
 * contains way more data than the V processor have seen.
 */
#define	SIZE_VIOLATION	(ctx->left >= 0 && (size_t)ctx->left <= size)

/*
 * This macro "eats" the part of the buffer which is definitely "consumed",
 * i.e. was correctly converted into local representation or rightfully skipped.
 */
#undef	ADVANCE
#define	ADVANCE(num_bytes)	do {		\
		size_t num = num_bytes;		\
		ptr = ((const char *)ptr) + num;\
		size -= num;			\
		if(ctx->left >= 0)		\
			ctx->left -= num;	\
		consumed_myself += num;		\
	} while(0)

/*
 * Switch to the next phase of parsing.
 */
#undef	NEXT_PHASE
#undef	PHASE_OUT
#define	NEXT_PHASE(ctx)	do {			\
		ctx->phase++;			\
		ctx->step = 0;			\
	} while(0)
#define	PHASE_OUT(ctx)	do { ctx->phase = 10; } while(0)

/*
 * Return a standardized complex structure.
 */
#undef	RETURN
#define	RETURN(_code)	do {			\
		rval.code = _code;		\
		rval.consumed = consumed_myself;\
		return rval;			\
	} while(0)

/*
 * The decoder of the SET OF type.
 */
asn_dec_rval_t
SET_OF_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td, void **struct_ptr,
                  const void *ptr, size_t size, int tag_mode) {
    /*
	 * Bring closer parts of structure description.
	 */
	const asn_SET_OF_specifics_t *specs = (const asn_SET_OF_specifics_t *)td->specifics;
    const asn_TYPE_member_t *elm = td->elements; /* Single one */

    /*
	 * Parts of the structure being constructed.
	 */
	void *st = *struct_ptr;	/* Target structure. */
	asn_struct_ctx_t *ctx;	/* Decoder context */

	ber_tlv_tag_t tlv_tag;	/* T from TLV */
	asn_dec_rval_t rval;	/* Return code from subparsers */

	ssize_t consumed_myself = 0;	/* Consumed bytes from ptr */

	ASN_DEBUG("Decoding %s as SET OF", td->name);
	
	/*
	 * Create the target structure if it is not present already.
	 */
	if(st == NULL) {
		st = *struct_ptr = CALLOC(1, specs->struct_size);
		if(st == NULL) {
			RETURN(RC_FAIL);
		}
	}

	/*
	 * Restore parsing context.
	 */
	ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);
	
	/*
	 * Start to parse where left previously
	 */
	switch(ctx->phase) {
	case 0:
		/*
		 * PHASE 0.
		 * Check that the set of tags associated with given structure
		 * perfectly fits our expectations.
		 */

		rval = ber_check_tags(opt_codec_ctx, td, ctx, ptr, size,
			tag_mode, 1, &ctx->left, NULL);
		if(rval.code != RC_OK) {
			ASN_DEBUG("%s tagging check failed: %d",
				td->name, rval.code);
			return rval;
		}

		if(ctx->left >= 0)
			ctx->left += rval.consumed; /* ?Substracted below! */
		ADVANCE(rval.consumed);

		ASN_DEBUG("Structure consumes %ld bytes, "
			"buffer %ld", (long)ctx->left, (long)size);

		NEXT_PHASE(ctx);
		/* Fall through */
	case 1:
		/*
		 * PHASE 1.
		 * From the place where we've left it previously,
		 * try to decode the next item.
		 */
	  for(;; ctx->step = 0) {
		ssize_t tag_len;	/* Length of TLV's T */

		if(ctx->step & 1)
			goto microphase2;

		/*
		 * MICROPHASE 1: Synchronize decoding.
		 */

		if(ctx->left == 0) {
			ASN_DEBUG("End of SET OF %s", td->name);
			/*
			 * No more things to decode.
			 * Exit out of here.
			 */
			PHASE_OUT(ctx);
			RETURN(RC_OK);
		}

		/*
		 * Fetch the T from TLV.
		 */
		tag_len = ber_fetch_tag(ptr, LEFT, &tlv_tag);
		switch(tag_len) {
		case 0: if(!SIZE_VIOLATION) RETURN(RC_WMORE);
			/* Fall through */
		case -1: RETURN(RC_FAIL);
		}

		if(ctx->left < 0 && ((const uint8_t *)ptr)[0] == 0) {
			if(LEFT < 2) {
				if(SIZE_VIOLATION)
					RETURN(RC_FAIL);
				else
					RETURN(RC_WMORE);
			} else if(((const uint8_t *)ptr)[1] == 0) {
				/*
				 * Found the terminator of the
				 * indefinite length structure.
				 */
				break;
			}
		}

		/* Outmost tag may be unknown and cannot be fetched/compared */
		if(elm->tag != (ber_tlv_tag_t)-1) {
		    if(BER_TAGS_EQUAL(tlv_tag, elm->tag)) {
			/*
			 * The new list member of expected type has arrived.
			 */
		    } else {
			ASN_DEBUG("Unexpected tag %s fixed SET OF %s",
				ber_tlv_tag_string(tlv_tag), td->name);
			ASN_DEBUG("%s SET OF has tag %s",
				td->name, ber_tlv_tag_string(elm->tag));
			RETURN(RC_FAIL);
		    }
		}

		/*
		 * MICROPHASE 2: Invoke the member-specific decoder.
		 */
		ctx->step |= 1;		/* Confirm entering next microphase */
	microphase2:
		
		/*
		 * Invoke the member fetch routine according to member's type
		 */
		rval = elm->type->op->ber_decoder(opt_codec_ctx,
				elm->type, &ctx->ptr, ptr, LEFT, 0);
		ASN_DEBUG("In %s SET OF %s code %d consumed %d",
			td->name, elm->type->name,
			rval.code, (int)rval.consumed);
		switch(rval.code) {
		case RC_OK:
			{
				asn_anonymous_set_ *list = _A_SET_FROM_VOID(st);
				if(ASN_SET_ADD(list, ctx->ptr) != 0)
					RETURN(RC_FAIL);
				else
					ctx->ptr = NULL;
			}
			break;
		case RC_WMORE: /* More data expected */
			if(!SIZE_VIOLATION) {
				ADVANCE(rval.consumed);
				RETURN(RC_WMORE);
			}
			/* Fall through */
		case RC_FAIL: /* Fatal error */
			ASN_STRUCT_FREE(*elm->type, ctx->ptr);
			ctx->ptr = NULL;
			RETURN(RC_FAIL);
		} /* switch(rval) */
		
		ADVANCE(rval.consumed);
	  }	/* for(all list members) */

		NEXT_PHASE(ctx);
	case 2:
		/*
		 * Read in all "end of content" TLVs.
		 */
		while(ctx->left < 0) {
			if(LEFT < 2) {
				if(LEFT > 0 && ((const char *)ptr)[0] != 0) {
					/* Unexpected tag */
					RETURN(RC_FAIL);
				} else {
					RETURN(RC_WMORE);
				}
			}
			if(((const char *)ptr)[0] == 0
			&& ((const char *)ptr)[1] == 0) {
				ADVANCE(2);
				ctx->left++;
			} else {
				RETURN(RC_FAIL);
			}
		}

		PHASE_OUT(ctx);
	}
	
	RETURN(RC_OK);
}

/*
 * Internally visible buffer holding a single encoded element.
 */
struct _el_buffer {
	uint8_t *buf;
	size_t length;
	size_t allocated_size;
    unsigned bits_unused;
};
/* Append bytes to the above structure */
static int _el_addbytes(const void *buffer, size_t size, void *el_buf_ptr) {
    struct _el_buffer *el_buf = (struct _el_buffer *)el_buf_ptr;

    if(el_buf->length + size > el_buf->allocated_size) {
        size_t new_size = el_buf->allocated_size ? el_buf->allocated_size : 8;
        void *p;

        do {
            new_size <<= 2;
        } while(el_buf->length + size > new_size);

        p = REALLOC(el_buf->buf, new_size);
        if(p) {
            el_buf->buf = p;
            el_buf->allocated_size = new_size;
        } else {
            return -1;
        }
    }

    memcpy(el_buf->buf + el_buf->length, buffer, size);

    el_buf->length += size;
    return 0;
}

static void assert_unused_bits(const struct _el_buffer* p) {
    if(p->length) {
        assert((p->buf[p->length-1] & ~(0xff << p->bits_unused)) == 0);
    } else {
        assert(p->bits_unused == 0);
    }
}

static int _el_buf_cmp(const void *ap, const void *bp) {
    const struct _el_buffer *a = (const struct _el_buffer *)ap;
    const struct _el_buffer *b = (const struct _el_buffer *)bp;
    size_t common_len;
    int ret = 0;

    if(a->length < b->length)
        common_len = a->length;
    else
        common_len = b->length;

    if (a->buf && b->buf) {
        ret = memcmp(a->buf, b->buf, common_len);
    }
    if(ret == 0) {
        if(a->length < b->length)
            ret = -1;
        else if(a->length > b->length)
            ret = 1;
        /* Ignore unused bits. */
        assert_unused_bits(a);
        assert_unused_bits(b);
    }

    return ret;
}

static void
SET_OF__encode_sorted_free(struct _el_buffer *el_buf, size_t count) {
    size_t i;

    for(i = 0; i < count; i++) {
        FREEMEM(el_buf[i].buf);
    }

    FREEMEM(el_buf);
}

enum SET_OF__encode_method {
    SOES_DER,   /* Distinguished Encoding Rules */
};

static struct _el_buffer *
SET_OF__encode_sorted(const asn_TYPE_member_t *elm,
                      const asn_anonymous_set_ *list,
                      enum SET_OF__encode_method method) {
    struct _el_buffer *encoded_els;
    int edx;

    encoded_els =
        (struct _el_buffer *)CALLOC(list->count, sizeof(encoded_els[0]));
    if(encoded_els == NULL) {
        return NULL;
    }

	/*
	 * Encode all members.
	 */
    for(edx = 0; edx < list->count; edx++) {
        const void *memb_ptr = list->array[edx];
        struct _el_buffer *encoding_el = &encoded_els[edx];
        asn_enc_rval_t erval;

        if(!memb_ptr) break;

        /*
		 * Encode the member into the prepared space.
		 */
        switch(method) {
        case SOES_DER:
            erval = elm->type->op->der_encoder(elm->type, memb_ptr, 0, elm->tag,
                                               _el_addbytes, encoding_el);
            break;
        default:
            assert(!"Unreachable");
            break;
        }
        if(erval.encoded < 0) break;
	}

    if(edx == list->count) {
        /*
         * Sort the encoded elements according to their encoding.
         */
        qsort(encoded_els, list->count, sizeof(encoded_els[0]), _el_buf_cmp);

        return encoded_els;
    } else {
        SET_OF__encode_sorted_free(encoded_els, edx);
        return NULL;
    }
}


/*
 * The DER encoder of the SET OF type.
 */
asn_enc_rval_t
SET_OF_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                  int tag_mode, ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb,
                  void *app_key) {
    const asn_TYPE_member_t *elm = td->elements;
    const asn_anonymous_set_ *list = _A_CSET_FROM_VOID(sptr);
    size_t computed_size = 0;
    ssize_t encoding_size = 0;
    struct _el_buffer *encoded_els;
    int edx;

	ASN_DEBUG("Estimating size for SET OF %s", td->name);

    /*
     * Gather the length of the underlying members sequence.
     */
    for(edx = 0; edx < list->count; edx++) {
        void *memb_ptr = list->array[edx];
        asn_enc_rval_t erval;

        if(!memb_ptr) ASN__ENCODE_FAILED;

        erval =
            elm->type->op->der_encoder(elm->type, memb_ptr, 0, elm->tag, NULL, NULL);
        if(erval.encoded == -1) return erval;
        computed_size += erval.encoded;
	}


    /*
     * Encode the TLV for the sequence itself.
     */
    encoding_size =
        der_write_tags(td, computed_size, tag_mode, 1, tag, cb, app_key);
    if(encoding_size < 0) {
        ASN__ENCODE_FAILED;
    }
    computed_size += encoding_size;

    if(!cb || list->count == 0) {
        asn_enc_rval_t erval;
        erval.encoded = computed_size;
        ASN__ENCODED_OK(erval);
    }

    ASN_DEBUG("Encoding members of %s SET OF", td->name);

    /*
     * DER mandates dynamic sorting of the SET OF elements
     * according to their encodings. Build an array of the
     * encoded elements.
     */
    encoded_els = SET_OF__encode_sorted(elm, list, SOES_DER);

    /*
     * Report encoded elements to the application.
     * Dispose of temporary sorted members table.
     */
    for(edx = 0; edx < list->count; edx++) {
        struct _el_buffer *encoded_el = &encoded_els[edx];
        /* Report encoded chunks to the application */
        if(cb(encoded_el->buf, encoded_el->length, app_key) < 0) {
            break;
        } else {
            encoding_size += encoded_el->length;
        }
    }

    SET_OF__encode_sorted_free(encoded_els, list->count);

    if(edx == list->count) {
        asn_enc_rval_t erval;
        assert(computed_size == (size_t)encoding_size);
        erval.encoded = computed_size;
        ASN__ENCODED_OK(erval);
    } else {
        ASN__ENCODE_FAILED;
    }
}

json_t *
SET_OF_encode_json(const struct asn_TYPE_descriptor_s *td, const void *sptr)
{
	json_t *parent;
	json_t *child;
	const asn_anonymous_set_ *list;
	asn_TYPE_descriptor_t *type;
	int i;

	if (!sptr)
		return json_null();

	parent = json_array_new();
	if (parent == NULL)
		return NULL;

	list = _A_CSET_FROM_VOID(sptr);
	type = td->elements->type;

	for (i = 0; i < list->count; i++) {
		child = type->op->json_encoder(type, list->array[i]);
		if (json_array_add(parent, child))
			goto fail;
	}

	return parent;

fail:	json_decref(parent);
	return NULL;
}

typedef struct xer_tmp_enc_s {
	void *buffer;
	size_t offset;
	size_t size;
} xer_tmp_enc_t;
static int
SET_OF_encode_xer_callback(const void *buffer, size_t size, void *key) {
	xer_tmp_enc_t *t = (xer_tmp_enc_t *)key;
	if(t->offset + size >= t->size) {
		size_t newsize = (t->size << 2) + size;
		void *p = REALLOC(t->buffer, newsize);
		if(!p) return -1;
		t->buffer = p;
		t->size = newsize;
	}
	memcpy((char *)t->buffer + t->offset, buffer, size);
	t->offset += size;
	return 0;
}
static int
SET_OF_xer_order(const void *aptr, const void *bptr) {
	const xer_tmp_enc_t *a = (const xer_tmp_enc_t *)aptr;
	const xer_tmp_enc_t *b = (const xer_tmp_enc_t *)bptr;
	size_t minlen = a->offset;
	int ret;
	if(b->offset < minlen) minlen = b->offset;
	/* Well-formed UTF-8 has this nice lexicographical property... */
	ret = memcmp(a->buffer, b->buffer, minlen);
	if(ret != 0) return ret;
	if(a->offset == b->offset)
		return 0;
	if(a->offset == minlen)
		return -1;
	return 1;
}


asn_enc_rval_t
SET_OF_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
                  int flags, asn_app_consume_bytes_f *cb,
                  void *app_key) {
    asn_enc_rval_t er;
	const asn_SET_OF_specifics_t *specs = (const asn_SET_OF_specifics_t *)td->specifics;
	const asn_TYPE_member_t *elm = td->elements;
    const asn_anonymous_set_ *list = _A_CSET_FROM_VOID(sptr);
    const char *mname = specs->as_XMLValueList
		? NULL : ((*elm->name) ? elm->name : elm->type->xml_tag);
	size_t mlen = mname ? strlen(mname) : 0;
	int xcan = (flags & XER_F_CANONICAL);
	xer_tmp_enc_t *encs = NULL;
	size_t encs_count = 0;
	void *original_app_key = app_key;
	asn_app_consume_bytes_f *original_cb = cb;
	int i;

	if(!sptr) ASN__ENCODE_FAILED;

	if(xcan) {
		encs = (xer_tmp_enc_t *)MALLOC(list->count * sizeof(encs[0]));
		if(!encs) ASN__ENCODE_FAILED;
		cb = SET_OF_encode_xer_callback;
	}

	er.encoded = 0;

	for(i = 0; i < list->count; i++) {
		asn_enc_rval_t tmper;

		void *memb_ptr = list->array[i];
		if(!memb_ptr) continue;

		if(encs) {
			memset(&encs[encs_count], 0, sizeof(encs[0]));
			app_key = &encs[encs_count];
			encs_count++;
		}

		if(mname) {
			if(!xcan) ASN__TEXT_INDENT(1, ilevel);
			ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);
		}

		if(!xcan && specs->as_XMLValueList == 1)
			ASN__TEXT_INDENT(1, ilevel + 1);
		tmper = elm->type->op->xer_encoder(elm->type, memb_ptr,
				ilevel + (specs->as_XMLValueList != 2),
				flags, cb, app_key);
		if(tmper.encoded == -1) return tmper;
		er.encoded += tmper.encoded;
		if(tmper.encoded == 0 && specs->as_XMLValueList) {
			const char *name = elm->type->xml_tag;
			size_t len = strlen(name);
			ASN__CALLBACK3("<", 1, name, len, "/>", 2);
		}

		if(mname) {
			ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
		}

	}

	if(!xcan) ASN__TEXT_INDENT(1, ilevel - 1);

	if(encs) {
		xer_tmp_enc_t *enc = encs;
		xer_tmp_enc_t *end = encs + encs_count;
		ssize_t control_size = 0;

		er.encoded = 0;
		cb = original_cb;
		app_key = original_app_key;
		qsort(encs, encs_count, sizeof(encs[0]), SET_OF_xer_order);

		for(; enc < end; enc++) {
			ASN__CALLBACK(enc->buffer, enc->offset);
			FREEMEM(enc->buffer);
			enc->buffer = NULL;
			control_size += enc->offset;
		}
		assert(control_size == er.encoded);
	}

	goto cleanup;
cb_failed:
	ASN__ENCODE_FAILED;
cleanup:
	if(encs) {
		size_t n;
		for(n = 0; n < encs_count; n++) {
			FREEMEM(encs[n].buffer);
		}
		FREEMEM(encs);
	}
	ASN__ENCODED_OK(er);
}

int
SET_OF_print(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
             asn_app_consume_bytes_f *cb, void *app_key) {
    asn_TYPE_member_t *elm = td->elements;
	const asn_anonymous_set_ *list = _A_CSET_FROM_VOID(sptr);
	int ret;
	int i;

	if(!sptr) return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;

	/* Dump preamble */
	if(cb(td->name, strlen(td->name), app_key) < 0
	|| cb(" ::= {", 6, app_key) < 0)
		return -1;

	for(i = 0; i < list->count; i++) {
		const void *memb_ptr = list->array[i];
		if(!memb_ptr) continue;

		_i_INDENT(1);

		ret = elm->type->op->print_struct(elm->type, memb_ptr,
			ilevel + 1, cb, app_key);
		if(ret) return ret;
	}

	ilevel--;
	_i_INDENT(1);

	return (cb("}", 1, app_key) < 0) ? -1 : 0;
}

void
SET_OF_free(const asn_TYPE_descriptor_t *td, void *ptr,
            enum asn_struct_free_method method) {
    if(td && ptr) {
		const asn_SET_OF_specifics_t *specs;
		asn_TYPE_member_t *elm = td->elements;
		asn_anonymous_set_ *list = _A_SET_FROM_VOID(ptr);
		asn_struct_ctx_t *ctx;	/* Decoder context */
		int i;

		/*
		 * Could not use set_of_empty() because of (*free)
		 * incompatibility.
		 */
		for(i = 0; i < list->count; i++) {
			void *memb_ptr = list->array[i];
			if(memb_ptr)
			ASN_STRUCT_FREE(*elm->type, memb_ptr);
		}
		list->count = 0;	/* No meaningful elements left */

		asn_set_empty(list);	/* Remove (list->array) */

		specs = (const asn_SET_OF_specifics_t *)td->specifics;
		ctx = (asn_struct_ctx_t *)((char *)ptr + specs->ctx_offset);
		if(ctx->ptr) {
			ASN_STRUCT_FREE(*elm->type, ctx->ptr);
			ctx->ptr = NULL;
		}

        switch(method) {
        case ASFM_FREE_EVERYTHING:
            FREEMEM(ptr);
            break;
        case ASFM_FREE_UNDERLYING:
            break;
        case ASFM_FREE_UNDERLYING_AND_RESET:
            memset(ptr, 0, specs->struct_size);
            break;
        }
    }
}

int
SET_OF_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                  asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    const asn_TYPE_member_t *elm = td->elements;
	asn_constr_check_f *constr;
	const asn_anonymous_set_ *list = _A_CSET_FROM_VOID(sptr);
	int i;

	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}

	constr = elm->encoding_constraints.general_constraints;
	if(!constr) constr = elm->type->encoding_constraints.general_constraints;

	/*
	 * Iterate over the members of an array.
	 * Validate each in turn, until one fails.
	 */
	for(i = 0; i < list->count; i++) {
		const void *memb_ptr = list->array[i];
		int ret;

		if(!memb_ptr) continue;

		ret = constr(elm->type, memb_ptr, ctfailcb, app_key);
		if(ret) return ret;
	}

	return 0;
}

struct comparable_ptr {
    const asn_TYPE_descriptor_t *td;
    const void *sptr;
};

static int
SET_OF__compare_cb(const void *aptr, const void *bptr) {
    const struct comparable_ptr *a = aptr;
    const struct comparable_ptr *b = bptr;
    assert(a->td == b->td);
    return a->td->op->compare_struct(a->td, a->sptr, b->sptr);
}

int
SET_OF_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
               const void *bptr) {
    const asn_anonymous_set_ *a = _A_CSET_FROM_VOID(aptr);
    const asn_anonymous_set_ *b = _A_CSET_FROM_VOID(bptr);

    if(a && b) {
        struct comparable_ptr *asorted;
        struct comparable_ptr *bsorted;
        ssize_t common_length;
        ssize_t idx;

        if(a->count == 0) {
            if(b->count) return -1;
            return 0;
        } else if(b->count == 0) {
            return 1;
        }

        asorted = MALLOC(a->count * sizeof(asorted[0]));
        bsorted = MALLOC(b->count * sizeof(bsorted[0]));
        if(!asorted || !bsorted) {
            FREEMEM(asorted);
            FREEMEM(bsorted);
            return -1;
        }

        for(idx = 0; idx < a->count; idx++) {
            asorted[idx].td = td->elements->type;
            asorted[idx].sptr = a->array[idx];
        }

        for(idx = 0; idx < b->count; idx++) {
            bsorted[idx].td = td->elements->type;
            bsorted[idx].sptr = b->array[idx];
        }

        qsort(asorted, a->count, sizeof(asorted[0]), SET_OF__compare_cb);
        qsort(bsorted, b->count, sizeof(bsorted[0]), SET_OF__compare_cb);

        common_length = (a->count < b->count ? a->count : b->count);
        for(idx = 0; idx < common_length; idx++) {
            int ret = td->elements->type->op->compare_struct(
                td->elements->type, asorted[idx].sptr, bsorted[idx].sptr);
            if(ret) {
                FREEMEM(asorted);
                FREEMEM(bsorted);
                return ret;
            }
        }

        FREEMEM(asorted);
        FREEMEM(bsorted);

        if(idx < b->count) /* more elements in b */
            return -1;     /* a is shorter, so put it first */
        if(idx < a->count) return 1;
    } else if(!a) {
        return -1;
    } else if(!b) {
        return 1;
    }

	return 0;
}


asn_TYPE_operation_t asn_OP_SET_OF = {
	SET_OF_free,
	SET_OF_print,
	SET_OF_compare,
	SET_OF_decode_ber,
	SET_OF_encode_der,
	SET_OF_encode_json,
	SET_OF_encode_xer,
	NULL	/* Use generic outmost tag fetcher */
};
