#ifndef SRC_STR_TOKEN_H_
#define SRC_STR_TOKEN_H_

#include <stdbool.h>
#include <stddef.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

int ia5s2string(ASN1_IA5STRING *, char **);
int BN2string(BIGNUM *, char **);

/* This file is named "str_token.h" because "string.h" collides with <string.h>. */

/**
 * Do not modify fields directly; this should be private.
 *
 * This is more or less like strtok(), except it doesn't modify the string at
 * any point.
 */
struct string_tokenizer {
	/** String we're tokenizing. */
	char const *str;
	size_t str_len;
	/** Token delimiter. */
	unsigned char separator;
	/** Offset of the first character of the current token. */
	size_t start;
	/** Offset of the last character of the current token + 1. */
	size_t end;
};

void string_tokenizer_init(struct string_tokenizer *, char const *, size_t,
    unsigned char);
bool string_tokenizer_next(struct string_tokenizer *);
bool token_equals(struct string_tokenizer *, struct string_tokenizer *);
int token_read(struct string_tokenizer *, char **);
size_t token_count(struct string_tokenizer *);

#endif /* SRC_STR_TOKEN_H_ */
