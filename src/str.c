#include "str.h"

#include <string.h>
#include "log.h"

/**
 * Does not assume that @string is NULL-terminated.
 */
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

void
string_tokenizer_init(struct string_tokenizer *tokenizer, char const *str,
    size_t str_len, unsigned char separator)
{
	tokenizer->str = str;
	tokenizer->str_len = str_len;
	tokenizer->separator = separator;
	tokenizer->start = 0;
	tokenizer->end = 0;
}

/**
 * Returns whether a new token was found.
 */
bool
string_tokenizer_next(struct string_tokenizer *tokenizer)
{
	size_t end = tokenizer->end;

	if (end == tokenizer->str_len)
		return false;

	if (end != 0) { /* end is pointing to a slash. */
		end++;
		if (end == tokenizer->str_len)
			return false;

		tokenizer->start = end;
	} /* otherwise it's pointing to the beginning of the string. */

	for (; end < tokenizer->str_len; end++)
		if (tokenizer->str[end] == tokenizer->separator)
			break;

	tokenizer->end = end;
	return true;
}

/**
 * Returns whether the tokens described by @t1 and @t2 are identical.
 */
bool
token_equals(struct string_tokenizer *t1, struct string_tokenizer *t2)
{
	size_t t1len = t1->end - t1->start;
	size_t t2len = t2->end - t2->start;
	return (t1len == t2len)
	    ? (memcmp(t1->str + t1->start, t2->str + t2->start, t1len) == 0)
	    : false;
}
