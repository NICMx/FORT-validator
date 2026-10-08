#ifndef COMMON_ALLOC_H_
#define COMMON_ALLOC_H_

#include <stddef.h>

/* malloc(), but panic on allocation failure. */
void *pmalloc(size_t size);
/* malloc(), but panic on allocation failure, zeroize memory on success. */
void *pzalloc(size_t size);
/* calloc(), but panic on allocation failure. */
void *pcalloc(size_t nmemb, size_t size);
/* realloc(), but panic on allocation failure. */
void *prealloc(void *ptr, size_t size);

/* strdup(), but panic on allocation failure. */
char *pstrdup(char const *s);
/* strndup(), but panic on allocation failure. */
char *pstrndup(char const *s, size_t n);

#endif /* COMMON_ALLOC_H_ */
