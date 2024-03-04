#ifndef SRC_ALLOC_H_
#define SRC_ALLOC_H_

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

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
char *pstrndup(char const *s, size_t size);

#endif /* SRC_ALLOC_H_ */
