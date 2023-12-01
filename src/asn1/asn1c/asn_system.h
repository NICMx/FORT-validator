/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * Miscellaneous system-dependent types.
 */
#ifndef	ASN_SYSTEM_H
#define	ASN_SYSTEM_H

#include <arpa/inet.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

#define	sys_ntohl(foo)	ntohl(foo)

#if	__GNUC__ >= 3 || defined(__clang__)
#define CC_ATTRIBUTE(attr)    __attribute__((attr))
#else
#define CC_ATTRIBUTE(attr)
#endif
#define CC_PRINTFLIKE(fmt, var)     CC_ATTRIBUTE(format(printf, fmt, var))
#define	CC_NOTUSED                  CC_ATTRIBUTE(unused)
#ifndef CC_ATTR_NO_SANITIZE
#define CC_ATTR_NO_SANITIZE(what)   CC_ATTRIBUTE(no_sanitize(what))
#endif

/* Figure out if thread safety is requested */
#if !defined(ASN_THREAD_SAFE) && (defined(THREAD_SAFE) || defined(_REENTRANT))
#define	ASN_THREAD_SAFE
#endif	/* Thread safety */

#ifndef	offsetof	/* If not defined by <stddef.h> */
#define	offsetof(s, m)	((ptrdiff_t)&(((s *)0)->m) - (ptrdiff_t)((s *)0))
#endif	/* offsetof */

#ifndef	MIN		/* Suitable for comparing primitive types (integers) */
#if defined(__GNUC__)
#define	MIN(a,b)	({ __typeof a _a = a; __typeof b _b = b;	\
	((_a)<(_b)?(_a):(_b)); })
#else	/* !__GNUC__ */
#define	MIN(a,b)	((a)<(b)?(a):(b))	/* Unsafe variant */
#endif /* __GNUC__ */
#endif	/* MIN */

#if __STDC_VERSION__ >= 199901L
#ifndef SIZE_MAX
#define SIZE_MAX   ((~((size_t)0)) >> 1)
#endif

#ifndef RSIZE_MAX   /* C11, Annex K */
#define RSIZE_MAX   (SIZE_MAX >> 1)
#endif
#ifndef RSSIZE_MAX   /* Halve signed size even further than unsigned */
#define RSSIZE_MAX   ((ssize_t)(RSIZE_MAX >> 1))
#endif
#else   /* Old compiler */
#undef  SIZE_MAX
#undef  RSIZE_MAX
#undef  RSSIZE_MAX
#define SIZE_MAX   ((~((size_t)0)) >> 1)
#define RSIZE_MAX   (SIZE_MAX >> 1)
#define RSSIZE_MAX   ((ssize_t)(RSIZE_MAX >> 1))
#endif

#if __STDC_VERSION__ >= 199901L
#define ASN_PRI_SIZE "zu"
#define ASN_PRI_SSIZE "zd"
#define ASN_PRIuMAX PRIuMAX
#define ASN_PRIdMAX PRIdMAX
#else
#define ASN_PRI_SIZE "lu"
#define ASN_PRI_SSIZE "ld"
#if LLONG_MAX > LONG_MAX
#define ASN_PRIuMAX "llu"
#define ASN_PRIdMAX "lld"
#else
#define ASN_PRIuMAX "lu"
#define ASN_PRIdMAX "ld"
#endif
#endif

#endif	/* ASN_SYSTEM_H */
