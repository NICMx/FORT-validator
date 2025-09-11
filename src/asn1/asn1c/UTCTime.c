/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "asn1/asn1c/UTCTime.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "asn1/asn1c/GeneralizedTime.h"
#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/xer_encoder.h"
#include "json_util.h"

#ifndef	ASN___INTERNAL_TEST_MODE

/*
 * UTCTime basic type description.
 */
static const ber_tlv_tag_t asn_DEF_UTCTime_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (23 << 2)),	/* [UNIVERSAL 23] IMPLICIT ...*/
	(ASN_TAG_CLASS_UNIVERSAL | (26 << 2)),  /* [UNIVERSAL 26] IMPLICIT ...*/
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))    /* ... OCTET STRING */
};
asn_TYPE_operation_t asn_OP_UTCTime = {
	OCTET_STRING_free,
	UTCTime_print,
	UTCTime_compare,
	OCTET_STRING_decode_ber,    /* Implemented in terms of OCTET STRING */
	OCTET_STRING_encode_der,    /* Implemented in terms of OCTET STRING */
	UTCTime_encode_json,
	UTCTime_encode_xer,
	NULL	/* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_UTCTime = {
	"UTCTime",
	"UTCTime",
	&asn_OP_UTCTime,
	asn_DEF_UTCTime_tags,
	sizeof(asn_DEF_UTCTime_tags)
	  / sizeof(asn_DEF_UTCTime_tags[0]) - 2,
	asn_DEF_UTCTime_tags,
	sizeof(asn_DEF_UTCTime_tags)
	  / sizeof(asn_DEF_UTCTime_tags[0]),
	{ NULL, NULL, UTCTime_constraint },
	NULL, 0,	/* No members */
	NULL	/* No specifics */
};

#endif	/* ASN___INTERNAL_TEST_MODE */

/*
 * Check that the time looks like the time.
 */
int
UTCTime_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                   asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    const UTCTime_t *st = (const UTCTime_t *)sptr;

    /* asn_UT2time() no longer supports NULL tm and no GMT. */
    fprintf(stderr, "UTCTime_constraint() is not implemented for now.\n");
    abort();

	if(asn_UT2time(st, NULL) != 0) {
        ASN__CTFAIL(app_key, td, sptr, "%s: Invalid time format: %s (%s:%d)",
                    td->name, strerror(errno), __FILE__, __LINE__);
        return -1;
	}

	return 0;
}

#ifndef	ASN___INTERNAL_TEST_MODE

asn_enc_rval_t
UTCTime_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int ilevel, int flags,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    if(flags & XER_F_CANONICAL) {
		asn_enc_rval_t rv;
		UTCTime_t *ut;
		struct tm tm;

		if(asn_UT2time((const UTCTime_t *)sptr, &tm) != 0)
			ASN__ENCODE_FAILED;

		/* Fractions are not allowed in UTCTime */
		ut = asn_time2UT(NULL, &tm);
		if(!ut) ASN__ENCODE_FAILED;

		rv = OCTET_STRING_encode_xer_utf8(td, sptr, ilevel, flags,
			cb, app_key);
		OCTET_STRING_free(&asn_DEF_UTCTime, ut, 0);
		return rv;
	} else {
		return OCTET_STRING_encode_xer_utf8(td, sptr, ilevel, flags,
			cb, app_key);
	}
}

#endif	/* ASN___INTERNAL_TEST_MODE */

static int
UTCTime2str(const UTCTime_t *st, char *str)
{
	struct tm tm;

	if (asn_UT2time(st, &tm) != 0)
		return -1;

	return asn_tm2str(&tm, str);
}

int
UTCTime_print(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
    asn_app_consume_bytes_f *cb, void *app_key)
{
	const UTCTime_t *st = (const UTCTime_t *)sptr;
	char buf[ASN_TM_STR_MAXLEN];
	int ret;

	if (st == NULL || st->buf == NULL)
		return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;

	ret = UTCTime2str(st, buf);
	if (ret < 0)
		return (cb("<bad-value>", 11, app_key) < 0) ? -1 : 0;

	return (cb(buf, ret, app_key) < 0) ? -1 : 0;
}

json_t *
UTCTime_encode_json(const asn_TYPE_descriptor_t *td, const void *sptr)
{
	const UTCTime_t *st = (const UTCTime_t *)sptr;
	char buf[ASN_TM_STR_MAXLEN];

	if (st == NULL || st->buf == NULL)
		return json_null();

	if (UTCTime2str(st, buf) < 0)
		return NULL;

	return json_str_new(buf);
}

time_t
asn_UT2time(const UTCTime_t *st, struct tm *_tm) {
	char buf[24];	/* "AAMMJJhhmmss+hhmm" + cushion */
	GeneralizedTime_t gt;

	if(!st || !st->buf
	|| st->size < 11 || st->size >= ((int)sizeof(buf) - 2)) {
		errno = EINVAL;
		return -1;
	}

	gt.buf = (unsigned char *)buf;
	gt.size = st->size + 2;
	memcpy(gt.buf + 2, st->buf, st->size);
	if(st->buf[0] > 0x35) {
		/* 19xx */
		gt.buf[0] = 0x31;
		gt.buf[1] = 0x39;
	} else {
		/* 20xx */
		gt.buf[0] = 0x32;
		gt.buf[1] = 0x30;
	}

	return asn_GT2time(&gt, _tm);
}

UTCTime_t *
asn_time2UT(UTCTime_t *opt_ut, const struct tm *tm) {
	GeneralizedTime_t *gt = (GeneralizedTime_t *)opt_ut;

	gt = asn_time2GT(gt, tm);
	if(gt == NULL) return NULL;

	assert(gt->size >= 2);
	gt->size -= 2;
	memmove(gt->buf, gt->buf + 2, gt->size + 1);

	return (UTCTime_t *)gt;
}

int
UTCTime_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
                        const void *bptr) {
    const GeneralizedTime_t *a = aptr;
    const GeneralizedTime_t *b = bptr;

    (void)td;

    /* asn_UT2time() no longer supports NULL tm and no GMT. */
    fprintf(stderr, "UTCTime_compare() is not implemented for now.\n");
    abort();

    if(a && b) {
        time_t at, bt;
        int aerr, berr;

        errno = EPERM;
        at = asn_UT2time(a, NULL);
        aerr = errno;
        errno = EPERM;
        bt = asn_UT2time(b, NULL);
        berr = errno;

        if(at == -1 && aerr != EPERM) {
            if(bt == -1 && berr != EPERM) {
                return OCTET_STRING_compare(td, aptr, bptr);
            } else {
                return -1;
            }
        } else if(bt == -1 && berr != EPERM) {
            return 1;
        } else {
            /* Both values are valid. */
        }

        if(at < bt) {
            return -1;
        } else if(at > bt) {
            return 1;
        } else {
            return 0;
        }
    } else if(!a && !b) {
        return 0;
    } else if(!a) {
        return -1;
    } else {
        return 1;
    }
}
