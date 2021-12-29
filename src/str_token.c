#include "str_token.h"

#include <errno.h>
#include <string.h>
#include "log.h"

/* Does not assume that @string is NULL-terminated. */
int
string_clone(void const *string, size_t size, char **clone)
{
	char *result;

	result = malloc(size + 1);
	if (result == NULL) {
		*clone = NULL;
		return pr_enomem();
	}

	memcpy(result, string, size);
	result[size] = '\0';

	*clone = result;
	return 0;
}

int
ia5s2string(ASN1_IA5STRING *ia5, char **result)
{
	return (ia5->flags & ASN1_STRING_FLAG_BITS_LEFT)
	    ? pr_val_err("CRL URI IA5String has unused bits.")
	    : string_clone(ia5->data, ia5->length, result);
}

int
BN2string(BIGNUM *bn, char **_result)
{
	BIO *bio;
	uint64_t written;
	char *result;

	/* Callers can call free() whether this function fails or not. */
	*_result = NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		return pr_enomem();

	if (BN_print(bio, bn) == 0) {
		BIO_free(bio);
		return val_crypto_err("Unable to print the BIGNUM into a BIO");
	}

	written = BIO_number_written(bio);
	result = malloc(written + 1);
	if (result == NULL) {
		BIO_free(bio);
		return pr_enomem();
	}

	BIO_read(bio, result, written);
	result[written] = '\0';

	BIO_free(bio);
	*_result = result;
	return 0;
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

	/* Ignore "empty" tokens */
	while (tokenizer->str[end] == tokenizer->separator) {
		end++;
		if (end == tokenizer->str_len) {
			tokenizer->start = end;
			tokenizer->end = end;
			return false;
		}
	}

	tokenizer->start = end;

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

int
token_read(struct string_tokenizer *tokenizer, char **token)
{
	return string_clone(tokenizer->str + tokenizer->start,
	    tokenizer->end - tokenizer->start, token);
}

size_t
token_count(struct string_tokenizer *tokenizer)
{
	struct string_tokenizer copy;
	size_t count;

	string_tokenizer_init(&copy, tokenizer->str, tokenizer->str_len,
	    tokenizer->separator);

	count = 0;
	while (string_tokenizer_next(&copy))
		count++;

	return count;
}
