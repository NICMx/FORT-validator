/*-
 * Copyright (c) 2003-2019 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#define	_POSIX_PTHREAD_SEMANTICS	/* for Sun */
#define	_REENTRANT			/* for Sun */
#define __EXTENSIONS__                  /* for Sun */

#include "asn1/asn1c/asn_internal.h"
#include "asn1/asn1c/GeneralizedTime.h"

#include <assert.h>
#include <errno.h>

#define	ATZVARS do {							\
	char tzoldbuf[64];						\
	char *tzold
#define	ATZSAVETZ do {							\
	tzold = getenv("TZ");						\
	if(tzold) {							\
		size_t tzlen = strlen(tzold);				\
		if(tzlen < sizeof(tzoldbuf)) {				\
			tzold = memcpy(tzoldbuf, tzold, tzlen + 1);	\
		} else {						\
			char *dupptr = tzold;				\
			tzold = MALLOC(tzlen + 1);			\
			if(tzold) memcpy(tzold, dupptr, tzlen + 1);	\
		}							\
		setenv("TZ", "UTC", 1);					\
	}								\
	tzset();							\
} while(0)
#define	ATZOLDTZ do {							\
	if (tzold) {							\
		setenv("TZ", tzold, 1);					\
		*tzoldbuf = 0;						\
		if(tzold != tzoldbuf)					\
			FREEMEM(tzold);					\
	} else {							\
		unsetenv("TZ");						\
	}								\
	tzset();							\
} while(0); } while(0);

#ifndef	ASN___INTERNAL_TEST_MODE

/*
 * GeneralizedTime basic type description.
 */
static const ber_tlv_tag_t asn_DEF_GeneralizedTime_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (24 << 2)),	/* [UNIVERSAL 24] IMPLICIT ...*/
	(ASN_TAG_CLASS_UNIVERSAL | (26 << 2)),  /* [UNIVERSAL 26] IMPLICIT ...*/
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))    /* ... OCTET STRING */
};
static asn_per_constraints_t asn_DEF_GeneralizedTime_per_constraints = {
	{ APC_CONSTRAINED, 7, 7, 0x20, 0x7e },  /* Value */
	{ APC_SEMI_CONSTRAINED, -1, -1, 0, 0 }, /* Size */
	0, 0
};
asn_TYPE_operation_t asn_OP_GeneralizedTime = {
	OCTET_STRING_free,
	GeneralizedTime_print,
	GeneralizedTime_compare,
	OCTET_STRING_decode_ber,    /* Implemented in terms of OCTET STRING */
	GeneralizedTime_encode_der,
	OCTET_STRING_decode_xer_utf8,
	GeneralizedTime_encode_xer,
#ifdef	ASN_DISABLE_OER_SUPPORT
	0,
	0,
#else
	OCTET_STRING_decode_oer,
	OCTET_STRING_encode_oer,
#endif  /* ASN_DISABLE_OER_SUPPORT */
#ifdef	ASN_DISABLE_PER_SUPPORT
	0,
	0,
#else
	OCTET_STRING_decode_uper,
	OCTET_STRING_encode_uper,
#endif	/* ASN_DISABLE_PER_SUPPORT */
	GeneralizedTime_random_fill,
	0	/* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_GeneralizedTime = {
	"GeneralizedTime",
	"GeneralizedTime",
	&asn_OP_GeneralizedTime,
	asn_DEF_GeneralizedTime_tags,
	sizeof(asn_DEF_GeneralizedTime_tags)
	  / sizeof(asn_DEF_GeneralizedTime_tags[0]) - 2,
	asn_DEF_GeneralizedTime_tags,
	sizeof(asn_DEF_GeneralizedTime_tags)
	  / sizeof(asn_DEF_GeneralizedTime_tags[0]),
	{ 0, &asn_DEF_GeneralizedTime_per_constraints, GeneralizedTime_constraint },
	0, 0,	/* No members */
	0	/* No specifics */
};

#endif	/* ASN___INTERNAL_TEST_MODE */

/*
 * Check that the time looks like the time.
 */
int
GeneralizedTime_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                           asn_app_constraint_failed_f *ctfailcb,
                           void *app_key) {
    const GeneralizedTime_t *st = (const GeneralizedTime_t *)sptr;

	/* asn_GT2time() no longer supports NULL tm and no GMT */
	fprintf(stderr, "GeneralizedTime_constraint() is not implemented for now.\n");
	abort();

	if(asn_GT2time(st, 0) != 0) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: Invalid time format: %s (%s:%d)",
			td->name, strerror(errno), __FILE__, __LINE__);
		return -1;
	}

	return 0;
}

asn_enc_rval_t
GeneralizedTime_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                           int tag_mode, ber_tlv_tag_t tag,
                           asn_app_consume_bytes_f *cb, void *app_key) {
    GeneralizedTime_t *st;
	asn_enc_rval_t erval;
	int fv, fd;	/* seconds fraction value and number of digits */
	struct tm tm;

	/*
	 * Encode as a canonical DER.
	 */
    if(asn_GT2time_frac((const GeneralizedTime_t *)sptr, &fv, &fd, &tm) != 0) {
        /* Failed to recognize time. Fail completely. */
		ASN__ENCODE_FAILED;
    }

    st = asn_time2GT_frac(0, &tm, fv, fd); /* Save time */
    if(!st) ASN__ENCODE_FAILED;               /* Memory allocation failure. */

    erval = OCTET_STRING_encode_der(td, st, tag_mode, tag, cb, app_key);

    ASN_STRUCT_FREE(*td, st);

    return erval;
}

#ifndef	ASN___INTERNAL_TEST_MODE

asn_enc_rval_t
GeneralizedTime_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                           int ilevel, enum xer_encoder_flags_e flags,
                           asn_app_consume_bytes_f *cb, void *app_key) {
    if(flags & XER_F_CANONICAL) {
		GeneralizedTime_t *gt;
		asn_enc_rval_t rv;
		int fv, fd;		/* fractional parts */
		struct tm tm;

		if(asn_GT2time_frac((const GeneralizedTime_t *)sptr,
					&fv, &fd, &tm) != 0)
			ASN__ENCODE_FAILED;

		gt = asn_time2GT_frac(0, &tm, fv, fd);
		if(!gt) ASN__ENCODE_FAILED;
	
		rv = OCTET_STRING_encode_xer_utf8(td, sptr, ilevel, flags,
			cb, app_key);
		ASN_STRUCT_FREE(asn_DEF_GeneralizedTime, gt);
		return rv;
	} else {
		return OCTET_STRING_encode_xer_utf8(td, sptr, ilevel, flags,
			cb, app_key);
	}
}

#endif	/* ASN___INTERNAL_TEST_MODE */

int
GeneralizedTime_print(const asn_TYPE_descriptor_t *td, const void *sptr,
                      int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
    const GeneralizedTime_t *st = (const GeneralizedTime_t *)sptr;

	(void)td;	/* Unused argument */
	(void)ilevel;	/* Unused argument */

	if(st && st->buf) {
		char buf[32];
		struct tm tm;
		int ret;

		if(asn_GT2time(st, &tm) != 0)
			return (cb("<bad-value>", 11, app_key) < 0) ? -1 : 0;

		ret = snprintf(buf, sizeof(buf),
			"%04d-%02d-%02d %02d:%02d:%02d (GMT)",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
		assert(ret > 0 && ret < (int)sizeof(buf));
		return (cb(buf, ret, app_key) < 0) ? -1 : 0;
	} else {
		return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;
	}
}

int
asn_GT2time(const GeneralizedTime_t *st, struct tm *ret_tm) {
	return asn_GT2time_frac(st, 0, 0, ret_tm);
}

time_t
asn_GT2time_prec(const GeneralizedTime_t *st, int *frac_value, int frac_digits, struct tm *ret_tm) {
	time_t tloc;
	int fv, fd = 0;

	if(frac_value)
		tloc = asn_GT2time_frac(st, &fv, &fd, ret_tm);
	else
		return asn_GT2time_frac(st, 0, 0, ret_tm);
	if(fd == 0 || frac_digits <= 0) {
		*frac_value = 0;
	} else {
		while(fd > frac_digits)
			fv /= 10, fd--;
		while(fd < frac_digits) {
			if(fv < INT_MAX / 10) {
				fv *= 10;
				fd++;
			} else {
				/* Too long precision request */
				fv = 0;
				break;
			}
		}

		*frac_value = fv;
	}

	return tloc;
}

/*
 * I had to tighten this up because timegm() is not standard.
 * This outright means time_t is out of reach, which is a nightmare.
 *
 * rfc6486#section-4.2.1:
 *
 *    The manifestNumber, thisUpdate, and nextUpdate fields are modeled
 *    after the corresponding fields in X.509 CRLs (see [RFC5280]).
 *
 * rfc5280#section-4.1.2.5.2:
 *
 *    GeneralizedTime values MUST be
 *    expressed in Greenwich Mean Time (Zulu) and MUST include seconds
 *    (i.e., times are YYYYMMDDHHMMSSZ)
 *
 * This requirement makes the problem more pallatable, because it means we can
 * convert the Generalized Time to a simple CST struct tm, and use that instead
 * of time_t.
 *
 * I left fractional seconds in place for now.
 *
 * The resulting tm is always in CST.
 */
int
asn_GT2time_frac(const GeneralizedTime_t *st, int *frac_value, int *frac_digits,
		 struct tm *ret_tm) {
	struct tm tm_s;
	uint8_t *buf;
	uint8_t *end;
	int fvalue = 0;
	int fdigits = 0;

	if(!st || !st->buf)
		goto garbage;

	buf = st->buf;
	end = buf + st->size;

	if(st->size < 10)
		goto garbage;

	/*
	 * Decode first 10 bytes: "AAAAMMJJhh"
	 */
	memset(&tm_s, 0, sizeof(tm_s));
#undef	B2F
#undef	B2T
#define	B2F(var)	do {					\
		unsigned ch = *buf;				\
		if(ch < 0x30 || ch > 0x39) {			\
			goto garbage;				\
		} else {					\
			var = var * 10 + (ch - 0x30);		\
			buf++;					\
		}						\
	} while(0)
#define	B2T(var)	B2F(tm_s.var)

	B2T(tm_year);	/* 1: A */
	B2T(tm_year);	/* 2: A */
	B2T(tm_year);	/* 3: A */
	B2T(tm_year);	/* 4: A */
	B2T(tm_mon);	/* 5: M */
	B2T(tm_mon);	/* 6: M */
	B2T(tm_mday);	/* 7: J */
	B2T(tm_mday);	/* 8: J */
	B2T(tm_hour);	/* 9: h */
	B2T(tm_hour);	/* 0: h */

	if(buf == end) goto garbage;

	/*
	 * Parse [mm[ss[(.|,)ffff]]]
	 *        ^^
	 */
	switch(*buf) {
	case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
	case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:
		tm_s.tm_min = (*buf++) - 0x30;
		if(buf == end) goto garbage;
		B2T(tm_min);
		break;
	default:		/* +, -, Z */
		goto garbage;
	}

	if(buf == end) goto garbage;

	/*
	 * Parse [mm[ss[(.|,)ffff]]]
	 *           ^^
	 */
	switch(*buf) {
	case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
	case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:
		tm_s.tm_sec = (*buf++) - 0x30;
		if(buf == end) goto garbage;
		B2T(tm_sec);
		break;
	default:		/* +, -, Z */
		goto garbage;
	}

	if(buf == end) goto garbage;

	/*
	 * Parse [mm[ss[(.|,)ffff]]]
	 *               ^ ^
	 */
	switch(*buf) {
	case 0x2C: case 0x2E: /* (.|,) */
		/*
		 * Process fractions of seconds.
		 */
		for(buf++; buf < end; buf++) {
			int v = *buf;
			/* GCC 4.x is being too smart without volatile */
			switch(v) {
			case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
			case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:
				if(fvalue < INT_MAX/10) {
					fvalue = fvalue * 10 + (v - 0x30);
					fdigits++;
				} else {
					/* Not enough precision, ignore */
				}
				continue;
			default:
				break;
			}
			break;
		}
	}

	if(buf == end) goto garbage;

	if ((*buf) != 0x5A) /* Zulu */
		goto garbage;

	/* Validation */
	if((tm_s.tm_mon > 12 || tm_s.tm_mon < 1)
	|| (tm_s.tm_mday > 31 || tm_s.tm_mday < 1)
	|| (tm_s.tm_hour > 23)
	|| (tm_s.tm_sec > 60)
	)
		goto garbage;

	/* Canonicalize */
	tm_s.tm_mon -= 1;	/* 0 - 11 */
	tm_s.tm_year -= 1900;
	tm_s.tm_isdst = 0;

	*ret_tm = tm_s;

	/* Fractions of seconds */
	if(frac_value) *frac_value = fvalue;
	if(frac_digits) *frac_digits = fdigits;

	return 0;

garbage:
	errno = EINVAL;
	return -1;
}

GeneralizedTime_t *
asn_time2GT(GeneralizedTime_t *opt_gt, const struct tm *tm) {
	return asn_time2GT_frac(opt_gt, tm, 0, 0);
}

GeneralizedTime_t *
asn_time2GT_frac(GeneralizedTime_t *opt_gt, const struct tm *tm, int frac_value, int frac_digits) {
	const unsigned int buf_size =
		4 + 2 + 2	/* yyyymmdd */
		+ 2 + 2 + 2	/* hhmmss */
		+ 1 + 9		/* .fffffffff */
		+ 1 + 4		/* +hhmm */
		+ 1		/* '\0' */
		;
	char *buf;
	char *p;
	int size;

	/* Check arguments */
	if(!tm) {
		errno = EINVAL;
		return 0;
	}

	/* Pre-allocate a buffer of sufficient yet small length */
	buf = (char *)MALLOC(buf_size);
	if(!buf) return 0;

	size = snprintf(buf, buf_size, "%04d%02d%02d%02d%02d%02d",
		tm->tm_year + 1900,
		tm->tm_mon + 1,
		tm->tm_mday,
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec
	);
	if(size != 14) {
		/* Could be assert(size == 14); */
		FREEMEM(buf);
		errno = EINVAL;
		return 0;
	}

	p = buf + size;

	/*
	 * Deal with fractions.
	 */
	if(frac_value > 0 && frac_digits > 0) {
		char *end = p + 1 + 9;	/* '.' + maximum 9 digits */
		char *z = p;
		long fbase;
		*z++ = '.';

		/* Place bounds on precision */
		while(frac_digits-- > 9)
			frac_value /= 10;

		/* emulate fbase = pow(10, frac_digits) */
		for(fbase = 1; frac_digits--;)
			fbase *= 10;

		do {
			int digit = frac_value / fbase;
			if(digit > 9) { z = 0; break; }
			*z++ = digit + 0x30;
			frac_value %= fbase;
			fbase /= 10;
		} while(fbase > 0 && frac_value > 0 && z < end);
		if(z) {
			for(--z; *z == 0x30; --z);	/* Strip zeroes */
			p = z + (*z != '.');
			size = p - buf;
		}
	}

	*p++ = 0x5a;	/* "Z" */
	*p++ = 0;
	size++;

	if(opt_gt) {
		if(opt_gt->buf)
			FREEMEM(opt_gt->buf);
	} else {
		opt_gt = (GeneralizedTime_t *)CALLOC(1, sizeof *opt_gt);
		if(!opt_gt) { FREEMEM(buf); return 0; }
	}

	opt_gt->buf = (unsigned char *)buf;
	opt_gt->size = size;

	return opt_gt;
}

asn_random_fill_result_t
GeneralizedTime_random_fill(const asn_TYPE_descriptor_t *td, void **sptr,
                              const asn_encoding_constraints_t *constraints,
                              size_t max_length) {
    asn_random_fill_result_t result_ok = {ARFILL_OK, 1};
    asn_random_fill_result_t result_failed = {ARFILL_FAILED, 0};
    asn_random_fill_result_t result_skipped = {ARFILL_SKIPPED, 0};
    static const char *values[] = {
        "19700101000000",    "19700101000000-0000",   "19700101000000+0000",
        "19700101000000Z",   "19700101000000.3Z",     "19821106210623.3",
        "19821106210629.3Z", "19691106210827.3-0500", "19821106210629.456",
    };
    size_t rnd = asn_random_between(0, sizeof(values)/sizeof(values[0])-1);

    (void)constraints;

    if(max_length < sizeof("yyyymmddhhmmss") && !*sptr) {
        return result_skipped;
    }

    if(*sptr) {
        if(OCTET_STRING_fromBuf(*sptr, values[rnd], -1) != 0) {
            if(!sptr) return result_failed;
        }
    } else {
        *sptr = OCTET_STRING_new_fromBuf(td, values[rnd], -1);
        if(!sptr) return result_failed;
    }

    return result_ok;
}

int
GeneralizedTime_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
                        const void *bptr) {
    const GeneralizedTime_t *a = aptr;
    const GeneralizedTime_t *b = bptr;

    (void)td;

    /* asn_GT2time_frac() no longer supports NULL tm and no GMT. */
    fprintf(stderr, "GeneralizedTime_compare() is not implemented for now.\n");
    abort();

    if(a && b) {
        int afrac_value, afrac_digits;
        int bfrac_value, bfrac_digits;
        int aerr, berr;
        time_t at, bt;

        errno = EPERM;
        at = asn_GT2time_frac(a, &afrac_value, &afrac_digits, 0);
        aerr = errno;
        errno = EPERM;
        bt = asn_GT2time_frac(b, &bfrac_value, &bfrac_digits, 0);
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
        } else if(afrac_digits == bfrac_digits) {
            if(afrac_value == bfrac_value) {
                return 0;
            }
            if(afrac_value < bfrac_value) {
                return -1;
            } else {
                return 1;
            }
        } else if(afrac_digits == 0) {
            return -1;
        } else if(bfrac_digits == 0) {
            return 1;
        } else {
            double afrac = (double)afrac_value / afrac_digits;
            double bfrac = (double)bfrac_value / bfrac_digits;
            if(afrac < bfrac) {
                return -1;
            } else if(afrac > bfrac) {
                return 1;
            } else {
                return 0;
            }
        }
    } else if(!a && !b) {
        return 0;
    } else if(!a) {
        return -1;
    } else {
        return 1;
    }

}
