/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn1/asn1c/OCTET_STRING.h"

#include <assert.h>
#include <errno.h>

#include "alloc.h"
#include "asn1/asn1c/BIT_STRING.h"
#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/ber_decoder.h"
#include "asn1/asn1c/der_encoder.h"
#include "asn1/asn1c/json_encoder.h"
#include "asn1/asn1c/xer_encoder.h"
#include "json_util.h"

/*
 * OCTET STRING basic type description.
 */
static const ber_tlv_tag_t asn_DEF_OCTET_STRING_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))
};
asn_OCTET_STRING_specifics_t asn_SPC_OCTET_STRING_specs = {
	sizeof(OCTET_STRING_t),
	offsetof(OCTET_STRING_t, _asn_ctx),
	ASN_OSUBV_STR
};

asn_TYPE_operation_t asn_OP_OCTET_STRING = {
	OCTET_STRING_free,
	OCTET_STRING_print,	/* OCTET STRING generally means a non-ascii sequence */
	OCTET_STRING_compare,
	OCTET_STRING_decode_ber,
	OCTET_STRING_encode_der,
	OCTET_STRING_encode_json,
	OCTET_STRING_encode_xer,
	NULL	/* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_OCTET_STRING = {
	"OCTET STRING",		/* Canonical name */
	"OCTET_STRING",		/* XML tag name */
	&asn_OP_OCTET_STRING,
	asn_DEF_OCTET_STRING_tags,
	sizeof(asn_DEF_OCTET_STRING_tags)
	  / sizeof(asn_DEF_OCTET_STRING_tags[0]),
	asn_DEF_OCTET_STRING_tags,	/* Same as above */
	sizeof(asn_DEF_OCTET_STRING_tags)
	  / sizeof(asn_DEF_OCTET_STRING_tags[0]),
	{ NULL, NULL, asn_generic_no_constraint },
	NULL, 0,	/* No members */
	&asn_SPC_OCTET_STRING_specs
};

#undef	_CH_PHASE
#undef	NEXT_PHASE
#undef	PREV_PHASE
#define	_CH_PHASE(ctx, inc) do {					\
		if(ctx->phase == 0)					\
			ctx->context = 0;				\
		ctx->phase += inc;					\
	} while(0)
#define	NEXT_PHASE(ctx)	_CH_PHASE(ctx, +1)
#define	PREV_PHASE(ctx)	_CH_PHASE(ctx, -1)

#undef	ADVANCE
#define	ADVANCE(num_bytes)	do {					\
		size_t num = (num_bytes);				\
		buf_ptr = ((const char *)buf_ptr) + num;		\
		size -= num;						\
		consumed_myself += num;					\
	} while(0)

#undef	RETURN
#define	RETURN(_code)	do {						\
		asn_dec_rval_t tmprval;					\
		tmprval.code = _code;					\
		tmprval.consumed = consumed_myself;			\
		return tmprval;						\
	} while(0)

#undef	APPEND
#define	APPEND(bufptr, bufsize)	do {					\
		size_t _bs = (bufsize);		/* Append size */	\
		size_t _ns = ctx->context;	/* Allocated now */	\
		size_t _es = st->size + _bs;	/* Expected size */	\
		/* int is really a typeof(st->size): */			\
		if((int)_es < 0) RETURN(RC_FAIL);			\
		if(_ns <= _es) {					\
			void *ptr;					\
			/* Be nice and round to the memory allocator */	\
			do { _ns = _ns ? _ns << 1 : 16; }		\
			    while(_ns <= _es);				\
			/* int is really a typeof(st->size): */		\
			if((int)_ns < 0) RETURN(RC_FAIL);		\
			ptr = REALLOC(st->buf, _ns);			\
			if(ptr) {					\
				st->buf = (uint8_t *)ptr;		\
				ctx->context = _ns;			\
			} else {					\
				RETURN(RC_FAIL);			\
			}						\
			ASN_DEBUG("Reallocating into %ld", (long)_ns);	\
		}							\
		memcpy(st->buf + st->size, bufptr, _bs);		\
		/* Convenient nul-termination */			\
		st->buf[_es] = '\0';					\
		st->size = _es;						\
	} while(0)

/*
 * The main reason why ASN.1 is still alive is that too much time and effort
 * is necessary for learning it more or less adequately, thus creating a gut
 * necessity to demonstrate that aquired skill everywhere afterwards.
 * No, I am not going to explain what the following stuff is.
 */
struct _stack_el {
    ber_tlv_len_t left;     /* What's left to read (or -1) */
    ber_tlv_len_t got;      /* What was actually processed */
    unsigned cont_level;    /* Depth of subcontainment */
    int want_nulls;         /* Want null "end of content" octets? */
    int bits_chopped;       /* Flag in BIT STRING mode */
    ber_tlv_tag_t tag;      /* For debugging purposes */
    struct _stack_el *prev;
    struct _stack_el *next;
};
struct _stack {
	struct _stack_el *tail;
	struct _stack_el *cur_ptr;
};

static struct _stack_el *
OS__add_stack_el(struct _stack *st) {
	struct _stack_el *nel;

	/*
	 * Reuse the old stack frame or allocate a new one.
	 */
	if(st->cur_ptr && st->cur_ptr->next) {
		nel = st->cur_ptr->next;
		nel->bits_chopped = 0;
		nel->got = 0;
		/* Retain the nel->cont_level, it's correct. */
	} else {
		nel = (struct _stack_el *)CALLOC(1, sizeof(struct _stack_el));
		if(nel == NULL)
			return NULL;
	
		if(st->tail) {
			/* Increase a subcontainment depth */
			nel->cont_level = st->tail->cont_level + 1;
			st->tail->next = nel;
		}
		nel->prev = st->tail;
		st->tail = nel;
	}

	st->cur_ptr = nel;

	return nel;
}

static struct _stack *
_new_stack(void) {
	return (struct _stack *)CALLOC(1, sizeof(struct _stack));
}

/*
 * Decode OCTET STRING type.
 */
asn_dec_rval_t
OCTET_STRING_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td, void **sptr,
                        const void *buf_ptr, size_t size, int tag_mode) {
    const asn_OCTET_STRING_specifics_t *specs = td->specifics
				? (const asn_OCTET_STRING_specifics_t *)td->specifics
				: &asn_SPC_OCTET_STRING_specs;
	BIT_STRING_t *st = (BIT_STRING_t *)*sptr;
	asn_dec_rval_t rval;
	asn_struct_ctx_t *ctx;
	ssize_t consumed_myself = 0;
	struct _stack *stck;		/* Expectations stack structure */
	struct _stack_el *sel = NULL;	/* Stack element */
	int tlv_constr;
	enum asn_OS_Subvariant type_variant = specs->subvariant;

	ASN_DEBUG("Decoding %s as %s (frame %ld)",
		td->name,
		(type_variant == ASN_OSUBV_STR) ?
			"OCTET STRING" : "OS-SpecialCase",
		(long)size);

	/*
	 * Create the string if does not exist.
	 */
	if(st == NULL) {
		st = (BIT_STRING_t *)(*sptr = CALLOC(1, specs->struct_size));
		if(st == NULL) RETURN(RC_FAIL);
	}

	/* Restore parsing context */
	ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);

	switch(ctx->phase) {
	case 0:
		/*
		 * Check tags.
		 */
		rval = ber_check_tags(opt_codec_ctx, td, ctx,
			buf_ptr, size, tag_mode, -1,
			&ctx->left, &tlv_constr);
		if(rval.code != RC_OK)
			return rval;

		if(tlv_constr) {
			/*
			 * Complex operation, requires stack of expectations.
			 */
			ctx->ptr = _new_stack();
			if(!ctx->ptr) {
				RETURN(RC_FAIL);
			}
		} else {
			/*
			 * Jump into stackless primitive decoding.
			 */
			_CH_PHASE(ctx, 3);
			if(type_variant == ASN_OSUBV_ANY && tag_mode != 1)
				APPEND(buf_ptr, rval.consumed);
			ADVANCE(rval.consumed);
			goto phase3;
		}

		NEXT_PHASE(ctx);
		/* Fall through */
	case 1:
	phase1:
		/*
		 * Fill the stack with expectations.
		 */
		stck = (struct _stack *)ctx->ptr;
		sel = stck->cur_ptr;
	  do {
		ber_tlv_tag_t tlv_tag;
		ber_tlv_len_t tlv_len;
		ber_tlv_tag_t expected_tag;
		ssize_t tl, ll, tlvl;
				/* This one works even if (sel->left == -1) */
		size_t Left = ((!sel||(size_t)sel->left >= size)
					?size:(size_t)sel->left);


		ASN_DEBUG("%p, s->l=%ld, s->wn=%ld, s->g=%ld\n", (void *)sel,
			(long)(sel?sel->left:0),
			(long)(sel?sel->want_nulls:0),
			(long)(sel?sel->got:0)
		);
		if(sel && sel->left <= 0 && sel->want_nulls == 0) {
			if(sel->prev) {
				struct _stack_el *prev = sel->prev;
				if(prev->left != -1) {
					if(prev->left < sel->got)
						RETURN(RC_FAIL);
					prev->left -= sel->got;
				}
				prev->got += sel->got;
				sel = stck->cur_ptr = prev;
				if(!sel) break;
				tlv_constr = 1;
				continue;
			} else {
				sel = stck->cur_ptr = NULL;
				break;	/* Nothing to wait */
			}
		}

		tl = ber_fetch_tag(buf_ptr, Left, &tlv_tag);
		ASN_DEBUG("fetch tag(size=%ld,L=%ld), %sstack, left=%ld, wn=%ld, tl=%ld",
			(long)size, (long)Left, sel?"":"!",
			(long)(sel?sel->left:0),
			(long)(sel?sel->want_nulls:0),
			(long)tl);
		switch(tl) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}

		tlv_constr = BER_TLV_CONSTRUCTED(buf_ptr);

		ll = ber_fetch_length(tlv_constr,
				(const char *)buf_ptr + tl,Left - tl,&tlv_len);
		ASN_DEBUG("Got tag=%s, tc=%d, left=%ld, tl=%ld, len=%ld, ll=%ld",
			ber_tlv_tag_string(tlv_tag), tlv_constr,
				(long)Left, (long)tl, (long)tlv_len, (long)ll);
		switch(ll) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}

		if(sel && sel->want_nulls
			&& ((const uint8_t *)buf_ptr)[0] == 0
			&& ((const uint8_t *)buf_ptr)[1] == 0)
		{

			ASN_DEBUG("Eat EOC; wn=%d--", sel->want_nulls);

			if(type_variant == ASN_OSUBV_ANY
			&& (tag_mode != 1 || sel->cont_level))
				APPEND("\0\0", 2);

			ADVANCE(2);
			sel->got += 2;
			if(sel->left != -1) {
				sel->left -= 2;	/* assert(sel->left >= 2) */
			}

			sel->want_nulls--;
			if(sel->want_nulls == 0) {
				/* Move to the next expectation */
				sel->left = 0;
				tlv_constr = 1;
			}

			continue;
		}

		/*
		 * Set up expected tags,
		 * depending on ASN.1 type being decoded.
		 */
		switch(type_variant) {
		case ASN_OSUBV_BIT:
			/* X.690: 8.6.4.1, NOTE 2 */
			/* Fall through */
		case ASN_OSUBV_STR:
		default:
			if(sel) {
				unsigned level = sel->cont_level;
				if(level < td->all_tags_count) {
					expected_tag = td->all_tags[level];
					break;
				} else if(td->all_tags_count) {
					expected_tag = td->all_tags
						[td->all_tags_count - 1];
					break;
				}
				/* else, Fall through */
			}
			/* Fall through */
		case ASN_OSUBV_ANY:
			expected_tag = tlv_tag;
			break;
		}


		if(tlv_tag != expected_tag) {
			char buf[2][32];
			ber_tlv_tag_snprint(tlv_tag,
				buf[0], sizeof(buf[0]));
			ber_tlv_tag_snprint(td->tags[td->tags_count-1],
				buf[1], sizeof(buf[1]));
			ASN_DEBUG("Tag does not match expectation: %s != %s",
				buf[0], buf[1]);
			RETURN(RC_FAIL);
		}

		tlvl = tl + ll;	/* Combined length of T and L encoding */
		if((tlv_len + tlvl) < 0) {
			/* tlv_len value is too big */
			ASN_DEBUG("TLV encoding + length (%ld) is too big",
				(long)tlv_len);
			RETURN(RC_FAIL);
		}

		/*
		 * Append a new expectation.
		 */
		sel = OS__add_stack_el(stck);
		if(!sel) RETURN(RC_FAIL);

		sel->tag = tlv_tag;

		sel->want_nulls = (tlv_len==-1);
		if(sel->prev && sel->prev->left != -1) {
			/* Check that the parent frame is big enough */
			if(sel->prev->left < tlvl + (tlv_len==-1?0:tlv_len))
				RETURN(RC_FAIL);
			if(tlv_len == -1)
				sel->left = sel->prev->left - tlvl;
			else
				sel->left = tlv_len;
		} else {
			sel->left = tlv_len;
		}
		if(type_variant == ASN_OSUBV_ANY
		&& (tag_mode != 1 || sel->cont_level))
			APPEND(buf_ptr, tlvl);
		sel->got += tlvl;
		ADVANCE(tlvl);

		ASN_DEBUG("+EXPECT2 got=%ld left=%ld, wn=%d, clvl=%u",
			(long)sel->got, (long)sel->left,
			sel->want_nulls, sel->cont_level);

	  } while(tlv_constr);
		if(sel == NULL) {
			/* Finished operation, "phase out" */
			ASN_DEBUG("Phase out");
			_CH_PHASE(ctx, +3);
			break;
		}

		NEXT_PHASE(ctx);
		/* Fall through */
	case 2:
		stck = (struct _stack *)ctx->ptr;
		sel = stck->cur_ptr;
		ASN_DEBUG("Phase 2: Need %ld bytes, size=%ld, alrg=%ld, wn=%d",
			(long)sel->left, (long)size, (long)sel->got,
				sel->want_nulls);
	    {
		ber_tlv_len_t len;

		assert(sel->left >= 0);

		len = ((ber_tlv_len_t)size < sel->left)
				? (ber_tlv_len_t)size : sel->left;
		if(len > 0) {
			if(type_variant == ASN_OSUBV_BIT
			&& sel->bits_chopped == 0) {
				/* Put the unused-bits-octet away */
				st->bits_unused = *(const uint8_t *)buf_ptr;
				APPEND(((const char *)buf_ptr+1), (len - 1));
				sel->bits_chopped = 1;
			} else {
				APPEND(buf_ptr, len);
			}
			ADVANCE(len);
			sel->left -= len;
			sel->got += len;
		}

		if(sel->left) {
			ASN_DEBUG("OS left %ld, size = %ld, wn=%d\n",
				(long)sel->left, (long)size, sel->want_nulls);
			RETURN(RC_WMORE);
		}

		PREV_PHASE(ctx);
		goto phase1;
	    }
		break;
	case 3:
	phase3:
		/*
		 * Primitive form, no stack required.
		 */
		assert(ctx->left >= 0);

		if(size < (size_t)ctx->left) {
			if(!size) RETURN(RC_WMORE);
			if(type_variant == ASN_OSUBV_BIT && !ctx->context) {
				st->bits_unused = *(const uint8_t *)buf_ptr;
				ctx->left--;
				ADVANCE(1);
			}
			APPEND(buf_ptr, size);
			assert(ctx->context > 0);
			ctx->left -= size;
			ADVANCE(size);
			RETURN(RC_WMORE);
		} else {
			if(type_variant == ASN_OSUBV_BIT
			&& !ctx->context && ctx->left) {
				st->bits_unused = *(const uint8_t *)buf_ptr;
				ctx->left--;
				ADVANCE(1);
			}
			APPEND(buf_ptr, ctx->left);
			ADVANCE(ctx->left);
			ctx->left = 0;

			NEXT_PHASE(ctx);
		}
		break;
	}

	if(sel) {
		ASN_DEBUG("3sel p=%p, wn=%d, l=%ld, g=%ld, size=%ld",
			(void *)sel->prev, sel->want_nulls,
			(long)sel->left, (long)sel->got, (long)size);
		if(sel->prev || sel->want_nulls > 1 || sel->left > 0) {
			RETURN(RC_WMORE);
		}
	}

	/*
	 * BIT STRING-specific processing.
	 */
	if(type_variant == ASN_OSUBV_BIT) {
        if(st->size) {
			if(st->bits_unused < 0 || st->bits_unused > 7) {
				RETURN(RC_FAIL);
			}
			/* Finalize BIT STRING: zero out unused bits. */
			st->buf[st->size-1] &= 0xff << st->bits_unused;
		} else {
			if(st->bits_unused) {
				RETURN(RC_FAIL);
			}
		}
	}

	ASN_DEBUG("Took %ld bytes to encode %s: [%s]:%ld",
		(long)consumed_myself, td->name,
		(type_variant == ASN_OSUBV_STR) ? (char *)st->buf : "<data>",
		(long)st->size);


	RETURN(RC_OK);
}

/*
 * Encode OCTET STRING type using DER.
 */
asn_enc_rval_t
OCTET_STRING_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                        int tag_mode, ber_tlv_tag_t tag,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er;
	const asn_OCTET_STRING_specifics_t *specs = td->specifics
				? (const asn_OCTET_STRING_specifics_t *)td->specifics
				: &asn_SPC_OCTET_STRING_specs;
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	enum asn_OS_Subvariant type_variant = specs->subvariant;
	int fix_last_byte = 0;

	ASN_DEBUG("%s %s as OCTET STRING",
		cb?"Estimating":"Encoding", td->name);

	/*
	 * Write tags.
	 */
	if(type_variant != ASN_OSUBV_ANY || tag_mode == 1) {
		er.encoded = der_write_tags(td,
				(type_variant == ASN_OSUBV_BIT) + st->size,
			tag_mode, type_variant == ASN_OSUBV_ANY, tag,
			cb, app_key);
		if(er.encoded == -1) {
			er.failed_type = td;
			er.structure_ptr = sptr;
			return er;
		}
	} else {
		/* Disallow: [<tag>] IMPLICIT ANY */
		assert(type_variant != ASN_OSUBV_ANY || tag_mode != -1);
		er.encoded = 0;
	}

	if(!cb) {
		er.encoded += (type_variant == ASN_OSUBV_BIT) + st->size;
		ASN__ENCODED_OK(er);
	}

	/*
	 * Prepare to deal with the last octet of BIT STRING.
	 */
	if(type_variant == ASN_OSUBV_BIT) {
		uint8_t b = st->bits_unused & 0x07;
		if(b && st->size) fix_last_byte = 1;
		ASN__CALLBACK(&b, 1);
	}

	/* Invoke callback for the main part of the buffer */
	ASN__CALLBACK(st->buf, st->size - fix_last_byte);

	/* The last octet should be stripped off the unused bits */
	if(fix_last_byte) {
		uint8_t b = st->buf[st->size-1] & (0xff << st->bits_unused);
		ASN__CALLBACK(&b, 1);
	}

	ASN__ENCODED_OK(er);
cb_failed:
	ASN__ENCODE_FAILED;
}

json_t *
OCTET_STRING_encode_json(const struct asn_TYPE_descriptor_s *td,
			 const void *sptr)
{
	static const char * const H2C = "0123456789abcdef";
	const OCTET_STRING_t *os = sptr;
	uint8_t *buf, *end;
	char *result, *r;
	json_t *json;

	result = pmalloc(2 * os->size);

	buf = os->buf;
	end = buf + os->size;
	r = result;
	for (; buf < end; buf++) {
		*r++ = H2C[(*buf >> 4) & 0x0F];
		*r++ = H2C[(*buf     ) & 0x0F];
	}

	json = json_strn_new(result, 2 * os->size);

	free(result);
	return json;
}

json_t *
OCTET_STRING_encode_json_utf8(const struct asn_TYPE_descriptor_s *td,
			 const void *sptr)
{
	const OCTET_STRING_t *os = sptr;
	return json_strn_new((char const *) os->buf, os->size);
}

asn_enc_rval_t
OCTET_STRING_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                        int ilevel, int flags,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    const char * const h2c = "0123456789ABCDEF";
	const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
	asn_enc_rval_t er;
	char scratch[16 * 3 + 4];
	char *p = scratch;
	uint8_t *buf;
	uint8_t *end;
	size_t i;

	if(!st || (!st->buf && st->size))
		ASN__ENCODE_FAILED;

	er.encoded = 0;

	/*
	 * Dump the contents of the buffer in hexadecimal.
	 */
	buf = st->buf;
	end = buf + st->size;
	if(flags & XER_F_CANONICAL) {
		char *scend = scratch + (sizeof(scratch) - 2);
		for(; buf < end; buf++) {
			if(p >= scend) {
				ASN__CALLBACK(scratch, p - scratch);
				p = scratch;
			}
			*p++ = h2c[(*buf >> 4) & 0x0F];
			*p++ = h2c[*buf & 0x0F];
		}

		ASN__CALLBACK(scratch, p-scratch);	/* Dump the rest */
	} else {
		for(i = 0; buf < end; buf++, i++) {
			if(!(i % 16) && (i || st->size > 16)) {
				ASN__CALLBACK(scratch, p-scratch);
				p = scratch;
				ASN__TEXT_INDENT(1, ilevel);
			}
			*p++ = h2c[(*buf >> 4) & 0x0F];
			*p++ = h2c[*buf & 0x0F];
			*p++ = 0x20;
		}
		if(p - scratch) {
			p--;	/* Remove the tail space */
			ASN__CALLBACK(scratch, p-scratch); /* Dump the rest */
			if(st->size > 16)
				ASN__TEXT_INDENT(1, ilevel-1);
		}
	}

	ASN__ENCODED_OK(er);
cb_failed:
	ASN__ENCODE_FAILED;
}

static const struct OCTET_STRING__xer_escape_table_s {
	const char *string;
	int size;
} OCTET_STRING__xer_escape_table[] = {
#define	OSXET(s)	{ s, sizeof(s) - 1 }
	OSXET("\074\156\165\154\057\076"),	/* <nul/> */
	OSXET("\074\163\157\150\057\076"),	/* <soh/> */
	OSXET("\074\163\164\170\057\076"),	/* <stx/> */
	OSXET("\074\145\164\170\057\076"),	/* <etx/> */
	OSXET("\074\145\157\164\057\076"),	/* <eot/> */
	OSXET("\074\145\156\161\057\076"),	/* <enq/> */
	OSXET("\074\141\143\153\057\076"),	/* <ack/> */
	OSXET("\074\142\145\154\057\076"),	/* <bel/> */
	OSXET("\074\142\163\057\076"),		/* <bs/> */
	OSXET("\011"),				/* \t */
	OSXET("\012"),				/* \n */
	OSXET("\074\166\164\057\076"),		/* <vt/> */
	OSXET("\074\146\146\057\076"),		/* <ff/> */
	OSXET("\015"),				/* \r */
	OSXET("\074\163\157\057\076"),		/* <so/> */
	OSXET("\074\163\151\057\076"),		/* <si/> */
	OSXET("\074\144\154\145\057\076"),	/* <dle/> */
	OSXET("\074\144\143\061\057\076"),	/* <de1/> */
	OSXET("\074\144\143\062\057\076"),	/* <de2/> */
	OSXET("\074\144\143\063\057\076"),	/* <de3/> */
	OSXET("\074\144\143\064\057\076"),	/* <de4/> */
	OSXET("\074\156\141\153\057\076"),	/* <nak/> */
	OSXET("\074\163\171\156\057\076"),	/* <syn/> */
	OSXET("\074\145\164\142\057\076"),	/* <etb/> */
	OSXET("\074\143\141\156\057\076"),	/* <can/> */
	OSXET("\074\145\155\057\076"),		/* <em/> */
	OSXET("\074\163\165\142\057\076"),	/* <sub/> */
	OSXET("\074\145\163\143\057\076"),	/* <esc/> */
	OSXET("\074\151\163\064\057\076"),	/* <is4/> */
	OSXET("\074\151\163\063\057\076"),	/* <is3/> */
	OSXET("\074\151\163\062\057\076"),	/* <is2/> */
	OSXET("\074\151\163\061\057\076"),	/* <is1/> */
	{ NULL, 0 },	/* " " */
	{ NULL, 0 },	/* ! */
	{ NULL, 0 },	/* \" */
	{ NULL, 0 },	/* # */
	{ NULL, 0 },	/* $ */
	{ NULL, 0 },	/* % */
	OSXET("\046\141\155\160\073"),	/* &amp; */
	{ NULL, 0 },	/* ' */
	{NULL,0},{NULL,0},{NULL,0},{NULL,0},	/* ()*+ */
	{NULL,0},{NULL,0},{NULL,0},{NULL,0},	/* ,-./ */
	{NULL,0},{NULL,0},{NULL,0},{NULL,0},	/* 0123 */
	{NULL,0},{NULL,0},{NULL,0},{NULL,0},	/* 4567 */
	{NULL,0},{NULL,0},{NULL,0},{NULL,0},	/* 89:; */
	OSXET("\046\154\164\073"),		/* &lt; */
	{ NULL, 0 },	/* = */
	OSXET("\046\147\164\073"),	/* &gt; */
};

asn_enc_rval_t
OCTET_STRING_encode_xer_utf8(const asn_TYPE_descriptor_t *td, const void *sptr,
                             int ilevel, int flags,
                             asn_app_consume_bytes_f *cb, void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
	asn_enc_rval_t er;
	uint8_t *buf, *end;
	uint8_t *ss;	/* Sequence start */
	ssize_t encoded_len = 0;

	(void)ilevel;	/* Unused argument */
	(void)flags;	/* Unused argument */

	if(!st || (!st->buf && st->size))
		ASN__ENCODE_FAILED;

	buf = st->buf;
	end = buf + st->size;
	for(ss = buf; buf < end; buf++) {
		unsigned int ch = *buf;
		int s_len;	/* Special encoding sequence length */

		/*
		 * Escape certain characters: X.680/11.15
		 */
		if(ch < sizeof(OCTET_STRING__xer_escape_table)
			/sizeof(OCTET_STRING__xer_escape_table[0])
		&& (s_len = OCTET_STRING__xer_escape_table[ch].size)) {
			if(((buf - ss) && cb(ss, buf - ss, app_key) < 0)
			|| cb(OCTET_STRING__xer_escape_table[ch].string, s_len,
					app_key) < 0)
				ASN__ENCODE_FAILED;
			encoded_len += (buf - ss) + s_len;
			ss = buf + 1;
		}
	}

	encoded_len += (buf - ss);
	if((buf - ss) && cb(ss, buf - ss, app_key) < 0)
		ASN__ENCODE_FAILED;

	er.encoded = encoded_len;
	ASN__ENCODED_OK(er);
}

int
OCTET_STRING_print(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
    const char * const h2c = "0123456789ABCDEF";
	const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
	char scratch[16 * 3 + 4];
	char *p = scratch;
	uint8_t *buf;
	uint8_t *end;
	size_t i;

	(void)td;	/* Unused argument */

	if(!st || (!st->buf && st->size))
		return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;

	/*
	 * Dump the contents of the buffer in hexadecimal.
	 */
	buf = st->buf;
	end = buf + st->size;
	for(i = 0; buf < end; buf++, i++) {
		if(!(i % 16) && (i || st->size > 16)) {
			if(cb(scratch, p - scratch, app_key) < 0)
				return -1;
			_i_INDENT(1);
			p = scratch;
		}
		*p++ = h2c[(*buf >> 4) & 0x0F];
		*p++ = h2c[*buf & 0x0F];
		*p++ = 0x20;
	}

	if(p > scratch) {
		p--;	/* Remove the tail space */
		if(cb(scratch, p - scratch, app_key) < 0)
			return -1;
	}

	return 0;
}

int
OCTET_STRING_print_utf8(const asn_TYPE_descriptor_t *td, const void *sptr,
                        int ilevel, asn_app_consume_bytes_f *cb,
                        void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;

	(void)td;	/* Unused argument */
	(void)ilevel;	/* Unused argument */

	if(st && (st->buf || !st->size)) {
		return (cb(st->buf, st->size, app_key) < 0) ? -1 : 0;
	} else {
		return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;
	}
}

void
OCTET_STRING_free(const asn_TYPE_descriptor_t *td, void *sptr,
                  enum asn_struct_free_method method) {
	OCTET_STRING_t *st = (OCTET_STRING_t *)sptr;
	const asn_OCTET_STRING_specifics_t *specs;
	asn_struct_ctx_t *ctx;
	struct _stack *stck;

	if(!td || !st)
		return;

	specs = td->specifics
		    ? (const asn_OCTET_STRING_specifics_t *)td->specifics
		    : &asn_SPC_OCTET_STRING_specs;
	ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);

	ASN_DEBUG("Freeing %s as OCTET STRING", td->name);

	if(st->buf) {
		FREEMEM(st->buf);
		st->buf = NULL;
	}

	/*
	 * Remove decode-time stack.
	 */
	stck = (struct _stack *)ctx->ptr;
	if(stck) {
		while(stck->tail) {
			struct _stack_el *sel = stck->tail;
			stck->tail = sel->prev;
			FREEMEM(sel);
		}
		FREEMEM(stck);
	}

    switch(method) {
    case ASFM_FREE_EVERYTHING:
        FREEMEM(sptr);
        break;
    case ASFM_FREE_UNDERLYING:
        break;
    case ASFM_FREE_UNDERLYING_AND_RESET:
        memset(sptr, 0,
               td->specifics
                   ? ((const asn_OCTET_STRING_specifics_t *)(td->specifics))
                         ->struct_size
                   : sizeof(OCTET_STRING_t));
        break;
    }
}

/*
 * Conversion routines.
 */
int
OCTET_STRING_fromBuf(OCTET_STRING_t *st, const char *str, int len) {
	void *buf;

	if(st == NULL || (str == NULL && len)) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * Clear the OCTET STRING.
	 */
	if(str == NULL) {
		FREEMEM(st->buf);
		st->buf = NULL;
		st->size = 0;
		return 0;
	}

	/* Determine the original string size, if not explicitly given */
	if(len < 0)
		len = strlen(str);

	/* Allocate and fill the memory */
	buf = MALLOC(len + 1);
	if(buf == NULL)
		return -1;

	memcpy(buf, str, len);
	((uint8_t *)buf)[len] = '\0';	/* Couldn't use memcpy(len+1)! */
	FREEMEM(st->buf);
	st->buf = (uint8_t *)buf;
	st->size = len;

	return 0;
}

OCTET_STRING_t *
OCTET_STRING_new_fromBuf(const asn_TYPE_descriptor_t *td, const char *str,
                         int len) {
    const asn_OCTET_STRING_specifics_t *specs =
        td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                      : &asn_SPC_OCTET_STRING_specs;
    OCTET_STRING_t *st;

	st = (OCTET_STRING_t *)CALLOC(1, specs->struct_size);
	if(st && str && OCTET_STRING_fromBuf(st, str, len)) {
		FREEMEM(st);
		st = NULL;
	}

	return st;
}

json_t *
OCTET_STRING_to_json(const asn_TYPE_descriptor_t *td, OCTET_STRING_t const *ber)
{
	return ber2json(td, ber->buf, ber->size);
}

/*
 * Lexicographically compare the common prefix of both strings,
 * and if it is the same return -1 for the smallest string.
 */
int
OCTET_STRING_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
                     const void *bptr) {
    const asn_OCTET_STRING_specifics_t *specs = td->specifics;
    const OCTET_STRING_t *a = aptr;
    const OCTET_STRING_t *b = bptr;

    assert(!specs || specs->subvariant != ASN_OSUBV_BIT);

    if(a && b) {
        size_t common_prefix_size = a->size <= b->size ? a->size : b->size;
        int ret = memcmp(a->buf, b->buf, common_prefix_size);
        if(ret == 0) {
            /* Figure out which string with equal prefixes is longer. */
            if(a->size < b->size) {
                return -1;
            } else if(a->size > b->size) {
                return 1;
            } else {
                return 0;
            }
        } else {
            return ret < 0 ? -1 : 1;
        }
    } else if(!a && !b) {
        return 0;
    } else if(!a) {
        return -1;
    } else {
        return 1;
    }

}
