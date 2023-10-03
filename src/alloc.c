#include "alloc.h"

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

void *
pmclone(void const *src, size_t size)
{
	void *result;

	result = pmalloc(size);
	if (result == NULL)
		enomem_panic();
	memcpy(result, src, size);

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
