#include "common.h"

#include <errno.h>
#include <string.h>
#include "log.h"

char const *repository;
size_t repository_len;
int NID_rpkiManifest;
int NID_signedObject;
int NID_rpkiNotify;

int
string_clone(void const *string, size_t size, char **clone)
{
	char *result;

	result = malloc(size + 1);
	if (result == NULL)
		return pr_enomem();

	memcpy(result, string, size);
	result[size] = '\0';

	*clone = result;
	return 0;
}

int
ia5s2string(ASN1_IA5STRING *ia5, char **result)
{
	return (ia5->flags & ASN1_STRING_FLAG_BITS_LEFT)
	    ? pr_err("CRL URI IA5String has unused bits.")
	    : string_clone(ia5->data, ia5->length, result);
}
