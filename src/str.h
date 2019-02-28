#ifndef SRC_STR_H_
#define SRC_STR_H_

#include <stdbool.h>
#include <stddef.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

int string_clone(void const *, size_t, char **);
int ia5s2string(ASN1_IA5STRING *, char **);

/* This file is named "str.h" because "string.h" collides with <string.h>. */

/**
 * Do not modify fields directly; this should be private.
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

#endif /* SRC_STR_H_ */
