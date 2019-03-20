#ifndef _SRC_COMMON_H_
#define _SRC_COMMON_H_

/* __BEGIN_DECLS should be used at the beginning of your declarations,
   so that C++ compilers don't mangle their names.  Use __END_DECLS at
   the end of C declarations. */
#undef __BEGIN_DECLS
#undef __END_DECLS
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS /* empty */
# define __END_DECLS /* empty */
#endif

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define EUNIMPLEMENTED 566456

/*
 * FYI: The error functions are warn() and warnx().
 * warn() automatically appends the errno string message (strerror()), warnx()
 * does not.
 */

#endif /* _SRC_COMMON_H_ */
