#include "common.h"

#include <stdlib.h>
#include <string.h>

char *
str_clone(char const *original)
{
	char *result;
	result = malloc(strlen(original) + 1);
	if (result != NULL)
		strcpy(result, original);
	return result;
}
