#include "alloc.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"

void *
pmalloc(size_t size)
{
	void *result;

	result = malloc(size);
	if (result == NULL)
		enomem_panic();

	return result;
}

void *
pzalloc(size_t size)
{
	void *result;

	result = pmalloc(size);
	memset(result, 0, size);

	return result;
}

void *
pcalloc(size_t nmemb, size_t size)
{
	void *result;

	result = calloc(nmemb, size);
	if (result == NULL)
		enomem_panic();

	return result;
}

void *
prealloc(void *ptr, size_t size)
{
	void *result;

	result = realloc(ptr, size);
	if (result == NULL)
		enomem_panic();

	return result;
}

char *
pstrdup(const char *s)
{
	char *result;

	result = strdup(s);
	if (result == NULL)
		enomem_panic();

	return result;
}

char *
pstrndup(const char *s, size_t n)
{
	char *result;

	result = strndup(s, n);
	if (result == NULL)
		enomem_panic();

	return result;
}
